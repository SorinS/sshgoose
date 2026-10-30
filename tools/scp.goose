// goose-scp: copies files to or from a host over SFTP (ssh.sftp), as
// OpenSSH's scp does by default since 9.0:
//
//   goose-scp [-r] [-p] [-q] [-v] [-P port] [-i keyfile]... [-o option=value]...
//             [-J [user@]host[:port][,...]] source... target
//
// A remote file is [user@]host:path (an IPv6 host in brackets); a path
// with a slash before its first colon is local. All the sources are local
// and the target remote, or the sources are on one host and the target
// local. A remote path is relative to the home directory there, and ~ and
// ~user are expanded where the server has expand-path@openssh.com; a
// remote source's last part may be a pattern (*, ?, [...]). A target that
// is a directory gets each source by its name; several sources need one.
// -r copies directories, following symbolic links; -p keeps modification
// and access times and modes (without it a new file gets its source's
// mode, as the umask allows). The login is goose-ssh's (-P is the port, -i
// keys, -o options, known_hosts, -J jump hosts and ProxyCommand). Files that fail are reported and the
// rest still copied; the exit status is 1 if any failed. Not supported:
// a copy between two remote hosts, the legacy scp protocol (-O), the
// progress meter (-q is taken and does nothing).
import std;
import os;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import ssh.conn;
import ssh.sftp;
import .sysnet;
import .login;
import .fs;

let CHUNK: i64 = 32768;            // bytes per READ or WRITE, as OpenSSH's default
let MAX_REQUESTS: i64 = 64;        // requests in flight in a transfer, as OpenSSH's

// The SFTP session's bytes: requests not yet taken by the channel's
// window, and replies not yet read.
var tx: u8[>..] = [];
var rx: u8[>..] = [];
var next_id: u32 = 1;
var errors = 0;

// The connection, and where the session is.
struct Link {
    sock: i32, wsock: i32,          // read from, written to: one socket, or a proxy's pipes
    ch: i64, ready: bool, gone: bool,
    expand: bool,                   // the server has expand-path@openssh.com
    preserve: bool, deep: bool,
}

fn report(o: const login::Options&, s: const u8[:]) {
    sysnet::eprint(str(o.prog, ": ", s, "\n"));
    errors++;
}

fn send_all(sock: i32, out: u8[>..]&) -> bool {
    if out.len == 0 { return true; }
    let n = sysnet::net_write(sock, out);
    out.clear();
    return n >= 0;
}

// One round: requests into the channel as its window allows, what is to
// send sent, then what arrives (within wait_ms) fed in: data to rx, the
// login's events answered, the session opened and the subsystem asked
// for. False once the connection is gone.
fn pump(o: const login::Options&, cfg: ssh::ClientConfig&, c: ssh::Conn&, l: Link&, out: u8[>..]&, wait_ms: i32) -> bool {
    if l.gone { return false; }
    if l.ready && tx.len > 0 {
        let n = ssh::channel_send(c, l.ch, tx, out);
        if n > 0 {
            var rest: u8[>..] = [];
            rest.append(tx[n..]);
            tx.clear();
            tx.append(rest);
        }
    }
    if !send_all(l.wsock, out) { l.gone = true; return false; }
    var fds: i32[1] = [l.sock];
    var flags: u8[1] = [0];
    let nready = sysnet::net_poll_set(fds, flags, wait_ms);
    if flags[0] == 0 { return true; }
    var input: u8[>..] = [];
    let n = sysnet::read_some(l.sock, input);
    if n <= 0 { l.gone = true; return false; }
    var events: u8[>..] = [];
    let r = ssh::client_feed(c, cfg, input, out, events);
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok { break; }
        let le = login::login_event(o, cfg, c, e, events, out);
        if le < 0 {
            let w = send_all(l.wsock, out);
            sysnet::eprint(str(o.prog, ": host key verification failed\n"));
            l.gone = true;
            return false;
        }
        if le > 0 { continue; }
        let d = ssh::bytes(events, e.data);
        if e.kind == ssh::EV_AUTHENTICATED {
            login::log(o, str("authenticated as ", o.user));
            l.ch = ssh::open_session(c, out);
        } else if e.kind == ssh::EV_CHANNEL_OPENED && e.channel == l.ch {
            let ok2 = ssh::subsystem(c, l.ch, "sftp", out);
        } else if e.kind == ssh::EV_CHANNEL_OPEN_FAILED {
            sysnet::eprint(str(o.prog, ": channel refused: ", d, "\n"));
            l.gone = true;
        } else if e.kind == ssh::EV_REQUEST_REPLY && e.channel == l.ch {
            if e.value != 1 { sysnet::eprint(str(o.prog, ": the server has no sftp subsystem\n")); l.gone = true; }
            else {
                l.ready = true;
                ssh::sftp_init(tx);
            }
        } else if e.kind == ssh::EV_DATA && e.channel == l.ch {
            rx.append(d);
        } else if e.kind == ssh::EV_EXTENDED_DATA && e.channel == l.ch {
            sysnet::eprint(d);
        } else if e.kind == ssh::EV_CLOSE || e.kind == ssh::EV_EOF || e.kind == ssh::EV_DISCONNECT {
            if e.kind == ssh::EV_DISCONNECT { sysnet::eprint(str(o.prog, ": disconnected: ", d, "\n")); }
            l.gone = true;
        }
    }
    if !send_all(l.wsock, out) { l.gone = true; return false; }
    if ssh::failed(c) {
        sysnet::eprint(str(o.prog, ": connection failed: ", c.message, "\n"));
        l.gone = true;
        return false;
    }
    return !l.gone || rx.len > 0;
}

// The next whole SFTP packet received, waiting for it; empty if the
// connection ended first or the server sent one too long.
fn next_packet(o: const login::Options&, cfg: ssh::ClientConfig&, c: ssh::Conn&, l: Link&, out: u8[>..]&) -> u8[>..] {
    var pkt: u8[>..] = [];
    loop {
        let n = ssh::sftp_packet_len(rx);
        if n < 0 { sysnet::eprint(str(o.prog, ": the server sent a bad packet\n")); l.gone = true; return pkt; }
        if n > 0 {
            pkt.append(rx[..n]);
            var rest: u8[>..] = [];
            rest.append(rx[n..]);
            rx.clear();
            rx.append(rest);
            return pkt;
        }
        if !pump(o, cfg, c, l, out, 1000) && l.gone && ssh::sftp_packet_len(rx) == 0 { return pkt; }
    }
    return pkt;
}

fn new_id() -> u32 {
    let id = next_id;
    next_id++;
    return id;
}

// The reply to request `id`, waiting for it (replies to others, which
// there should be none of, are dropped); empty if the connection ended.
fn reply(o: const login::Options&, cfg: ssh::ClientConfig&, c: ssh::Conn&, l: Link&, out: u8[>..]&, id: u32) -> u8[>..] {
    loop {
        let p = next_packet(o, cfg, c, l, out);
        if p.len == 0 { return p; }
        let m, ok = ssh::sftp_parse(p);
        if ok && m.id == id { return p; }
    }
    var none: u8[>..] = [];
    return none;
}

// A reply's STATUS: its code and message (FX_CONNECTION_LOST for none).
fn status_of(p: const u8[:]) -> u32, u8[>..] {
    var text: u8[>..] = [];
    if p.len == 0 { text.append("Connection lost"); return ssh::FX_CONNECTION_LOST, text; }
    let m, ok = ssh::sftp_parse(p);
    let code, t = ssh::sftp_get_status(p, m);
    text.append(ssh::bytes(p, t));
    if text.len == 0 { text.append(ssh::sftp_status_text(code)); }
    return code, text;
}

// --- Remote calls, one at a time ----------------------------------------------------

struct Ctx { o: login::Options, l: Link }

fn call(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, req: const u8[:], id: u32) -> u8[>..] {
    tx.append(req);
    return reply(cx.o, cfg, c, cx.l, out, id);
}

// STAT (follow) or LSTAT: the attributes, and FX_OK or the error.
fn rstat(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, path: const u8[:], follow: bool) -> ssh::Attrs, u32, u8[>..] {
    let id = new_id();
    var req: u8[>..] = [];
    ssh::sftp_path_req(req, if follow { ssh::FXP_STAT } else { ssh::FXP_LSTAT }, id, path);
    let p = call(cx, cfg, c, out, req, id);
    let m, ok = ssh::sftp_parse(p);
    if ok && m.kind == ssh::FXP_ATTRS {
        var r = m.body;
        let a = ssh::get_attrs(r, p);
        if !r.bad { var none: u8[>..] = []; return a, ssh::FX_OK, none; }
    }
    let code, text = status_of(p);
    return ssh::no_attrs(), if code == ssh::FX_OK { ssh::FX_BAD_MESSAGE } else { code }, text;
}

// A request answered by a STATUS: FX_OK or the error and its message.
fn rsimple(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, req: const u8[:], id: u32) -> u32, u8[>..] {
    let p = call(cx, cfg, c, out, req, id);
    return status_of(p);
}

// A NAME reply's first name (REALPATH, expand-path).
fn rname(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, req: const u8[:], id: u32) -> u8[>..], u32, u8[>..] {
    let p = call(cx, cfg, c, out, req, id);
    let m, ok = ssh::sftp_parse(p);
    var name: u8[>..] = [];
    if ok && m.kind == ssh::FXP_NAME {
        var r = m.body;
        let n = ssh::get_u32(r, p);
        let f = ssh::get_string(r, p);
        if !r.bad && n >= 1 { name.append(ssh::bytes(p, f)); var none: u8[>..] = []; return name, ssh::FX_OK, none; }
    }
    let code, text = status_of(p);
    return name, if code == ssh::FX_OK { ssh::FX_BAD_MESSAGE } else { code }, text;
}

// OPEN or OPENDIR: the handle, and FX_OK or the error.
fn rhandle(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, req: const u8[:], id: u32) -> u8[>..], u32, u8[>..] {
    let p = call(cx, cfg, c, out, req, id);
    let m, ok = ssh::sftp_parse(p);
    var h: u8[>..] = [];
    if ok && m.kind == ssh::FXP_HANDLE {
        var r = m.body;
        let s = ssh::get_string(r, p);
        if !r.bad { h.append(ssh::bytes(p, s)); var none: u8[>..] = []; return h, ssh::FX_OK, none; }
    }
    let code, text = status_of(p);
    return h, if code == ssh::FX_OK { ssh::FX_BAD_MESSAGE } else { code }, text;
}

fn rclose(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, h: const u8[:]) -> u32, u8[>..] {
    let id = new_id();
    var req: u8[>..] = [];
    ssh::sftp_handle_req(req, ssh::FXP_CLOSE, id, h);
    return rsimple(cx, cfg, c, out, req, id);
}

// A remote path as the server takes it: "" is its working directory (the
// home directory), and ~ is expanded by the server if it can (else "~/" is
// the home directory too, being where relative paths start).
fn remote_path(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, path: const u8[:]) -> u8[>..], bool {
    var p: u8[>..] = [];
    if path.len == 0 { p.append("."); return p, true; }
    if path[0] != '~' { p.append(path); return p, true; }
    if cx.l.expand {
        let id = new_id();
        var req: u8[>..] = [];
        let mark = ssh::sftp_extended(req, id, "expand-path@openssh.com");
        ssh::put_string(req, path);
        ssh::sftp_end(req, mark);
        let name, code, text = rname(cx, cfg, c, out, req, id);
        if code == ssh::FX_OK { return name, true; }
        report(cx.o, str(path, ": ", text));
        return p, false;
    }
    if path == "~" { p.append("."); return p, true; }
    if path.starts_with("~/") { p.append(path[2..]); return p, true; }
    report(cx.o, str(path, ": the server cannot expand ~user"));
    return p, false;
}

// --- Transfers ------------------------------------------------------------------------

fn local_mode(perm: u32) -> u32 { perm & 0x1ff }      // 0777

// A local file to a remote one: WRITE requests in flight up to
// MAX_REQUESTS, each answered with a STATUS.
fn upload(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, src: const u8[:], st: const fs::Stat&, dst: const u8[:]) {
    let fd = fs::fs_open(src, ssh::FXF_READ, 0);
    if fd < 0 { report(cx.o, str(src, ": ", ssh::sftp_status_text(fs::status(fd)))); return; }
    login::log(cx.o, str("upload ", src, " -> ", dst));
    let id = new_id();
    var req: u8[>..] = [];
    ssh::sftp_open(req, id, dst, ssh::FXF_WRITE | ssh::FXF_CREAT | ssh::FXF_TRUNC, ssh::perm_attrs(local_mode(st.mode)));
    let h, code, text = rhandle(cx, cfg, c, out, req, id);
    if code != ssh::FX_OK { report(cx.o, str("dest open \"", dst, "\": ", text)); let x = fs::fs_close(fd); return; }
    var buf: u8[>..] = [];
    buf.resize(CHUNK, 0);
    var offset: u64 = 0;
    var in_flight = 0;
    var failed = false;
    var eof = false;
    loop {
        while !eof && !failed && in_flight < MAX_REQUESTS {
            let n = fs::fs_pread(fd, buf, offset);
            if n < 0 { report(cx.o, str(src, ": ", ssh::sftp_status_text(fs::status(n)))); failed = true; break; }
            if n == 0 { eof = true; break; }
            ssh::sftp_write(tx, new_id(), h, offset, buf[..n]);
            offset += n as! u64;
            in_flight++;
        }
        if in_flight == 0 { break; }
        let p = next_packet(cx.o, cfg, c, cx.l, out);
        if p.len == 0 { report(cx.o, str(dst, ": Connection lost")); return; }
        in_flight--;
        let wc, wt = status_of(p);
        if wc != ssh::FX_OK && !failed { report(cx.o, str(dst, ": write: ", wt)); failed = true; }
    }
    let x = fs::fs_close(fd);
    if !failed && cx.l.preserve {
        var a = ssh::no_attrs();
        a.flags = ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME;
        a.perm = st.mode & 0xfff;
        a.atime = st.atime as! u32;
        a.mtime = st.mtime as! u32;
        let sid = new_id();
        var sreq: u8[>..] = [];
        ssh::sftp_setstat(sreq, ssh::FXP_FSETSTAT, sid, h, a);
        let sc, stext = rsimple(cx, cfg, c, out, sreq, sid);
        if sc != ssh::FX_OK { report(cx.o, str(dst, ": set times: ", stext)); }
    }
    let cc, ctext = rclose(cx, cfg, c, out, h);
    if cc != ssh::FX_OK && !failed { report(cx.o, str(dst, ": close: ", ctext)); }
}

// A remote file to a local one: READ requests in flight up to
// MAX_REQUESTS at increasing offsets, a short reply's rest asked for
// again, until the server answers EOF; the data written where it goes.
fn download(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, src: const u8[:], a: ssh::Attrs, dst: const u8[:]) {
    login::log(cx.o, str("download ", src, " -> ", dst));
    let id = new_id();
    var req: u8[>..] = [];
    ssh::sftp_open(req, id, src, ssh::FXF_READ, ssh::no_attrs());
    let h, code, text = rhandle(cx, cfg, c, out, req, id);
    if code != ssh::FX_OK { report(cx.o, str(src, ": ", text)); return; }
    // As OpenSSH's: the owner may write it, whatever the source's mode.
    let fd = fs::fs_open(dst, ssh::FXF_WRITE | ssh::FXF_CREAT | ssh::FXF_TRUNC, local_mode(a.perm) | 0x80);
    if fd < 0 {
        report(cx.o, str(dst, ": ", ssh::sftp_status_text(fs::status(fd))));
        let x = rclose(cx, cfg, c, out, h);
        return;
    }
    // In flight: id, offset and length of each read asked for.
    var ids: u32[>..] = [];
    var offs: u64[>..] = [];
    var lens: u64[>..] = [];
    var next_off: u64 = 0;
    var eof = false;
    var failed = false;
    loop {
        while !eof && !failed && ids.len < MAX_REQUESTS {
            let rid = new_id();
            ssh::sftp_read(tx, rid, h, next_off, CHUNK as! u32);
            ids.push(rid);
            offs.push(next_off);
            lens.push(CHUNK as! u64);
            next_off += CHUNK as! u64;
        }
        if ids.len == 0 { break; }
        let p = next_packet(cx.o, cfg, c, cx.l, out);
        if p.len == 0 { report(cx.o, str(src, ": Connection lost")); let x = fs::fs_close(fd); return; }
        let m, ok = ssh::sftp_parse(p);
        var k = -1;
        for i in ids.len { if ids[i] == m.id { k = i; } }
        if !ok || k < 0 { report(cx.o, str(src, ": an unexpected reply")); failed = true; continue; }
        let off = offs[k];
        let len = lens[k];
        let x1 = swap_remove(ids, k);
        let x2 = swap_remove(offs, k);
        let x3 = swap_remove(lens, k);
        if m.kind == ssh::FXP_DATA {
            var r = m.body;
            let d = ssh::get_string(r, p);
            let n: u64 = (d.end - d.pos) as! u64;
            if r.bad || n > len { report(cx.o, str(src, ": a bad reply")); failed = true; continue; }
            if failed { continue; }
            let w = fs::fs_pwrite(fd, ssh::bytes(p, d), off, 0);
            if w < 0 { report(cx.o, str(dst, ": ", ssh::sftp_status_text(fs::status(w)))); failed = true; continue; }
            // A short read: the rest of it asked for again.
            if n < len && n > 0 {
                let rid = new_id();
                ssh::sftp_read(tx, rid, h, off + n, (len - n) as! u32);
                ids.push(rid);
                offs.push(off + n);
                lens.push(len - n);
            } else if n == 0 {
                eof = true;
            }
        } else {
            let sc, st = status_of(p);
            if sc == ssh::FX_EOF { eof = true; }
            else if !failed { report(cx.o, str(src, ": read: ", st)); failed = true; }
        }
    }
    if !failed && cx.l.preserve {
        let t = fs::fs_utimes("", fd, a.atime, a.mtime, 1);
        let m2 = fs::fs_chmod("", fd, a.perm & 0xfff, 1);
        if t < 0 || m2 < 0 { report(cx.o, str(dst, ": set times or mode: ", ssh::sftp_status_text(fs::status(::min(t, m2))))); }
    }
    let x = fs::fs_close(fd);
    let cc, ct = rclose(cx, cfg, c, out, h);
}

// A remote directory's entries, "." and ".." left out: "name" lines, and
// their attributes in the same order.
fn list_remote(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, dir: const u8[:], names: u8[>..]&, attrs: ssh::Attrs[>..]&) -> bool {
    let id = new_id();
    var req: u8[>..] = [];
    ssh::sftp_path_req(req, ssh::FXP_OPENDIR, id, dir);
    let h, code, text = rhandle(cx, cfg, c, out, req, id);
    if code != ssh::FX_OK { report(cx.o, str(dir, ": ", text)); return false; }
    loop {
        let rid = new_id();
        var rr: u8[>..] = [];
        ssh::sftp_handle_req(rr, ssh::FXP_READDIR, rid, h);
        let p = call(cx, cfg, c, out, rr, rid);
        let m, ok = ssh::sftp_parse(p);
        if !ok || m.kind != ssh::FXP_NAME {
            let sc, st = status_of(p);
            if sc != ssh::FX_EOF { report(cx.o, str(dir, ": ", st)); }
            break;
        }
        var r = m.body;
        let n = ssh::get_u32(r, p);
        for i in n {
            let f = ssh::get_string(r, p);
            let lg = ssh::get_string(r, p);
            let a = ssh::get_attrs(r, p);
            if r.bad { break; }
            let name = ssh::bytes(p, f);
            if name == "." || name == ".." || position(name, '/') >= 0 || position(name, '\n') >= 0 { continue; }
            names.append(name);
            names.push('\n');
            attrs.push(a);
        }
        if r.bad { report(cx.o, str(dir, ": a bad reply")); break; }
    }
    let cc, ct = rclose(cx, cfg, c, out, h);
    return true;
}

// The work of a copy with -r: jobs on a stack, each a kind, the source,
// the destination and (downloads) the source's attributes, so that a tree
// is walked without recursion, its entries in their listing's order.
let JOB_COPY: u8 = 1;
let JOB_DIR_DONE: u8 = 2;          // a directory's entries are done: its times and mode, with -p

var jobs: u8[>..] = [];
var job_starts: i64[>..] = [];

fn push_job(kind: u8, src: const u8[:], dst: const u8[:], a: ssh::Attrs) {
    job_starts.push(jobs.len);
    jobs.push(kind);
    ssh::put_string(jobs, src);
    ssh::put_string(jobs, dst);
    ssh::put_attrs(jobs, a);
}

fn pop_job() -> u8, u8[>..], u8[>..], ssh::Attrs, bool {
    var src: u8[>..] = [];
    var dst: u8[>..] = [];
    if job_starts.len == 0 { return 0, src, dst, ssh::no_attrs(), false; }
    let at = job_starts.pop();
    var r = ssh::rd_at(at, jobs.len);
    let kind = ssh::get_u8(r, jobs);
    let s1 = ssh::get_string(r, jobs);
    let s2 = ssh::get_string(r, jobs);
    let a = ssh::get_attrs(r, jobs);
    src.append(ssh::bytes(jobs, s1));
    dst.append(ssh::bytes(jobs, s2));
    jobs.resize(at, 0);
    return kind, src, dst, a, true;
}

// Pushes a directory's entries (names, one per line) in reverse, so that
// they come off the stack in order.
fn push_entries(names: const u8[:], attrs: const ssh::Attrs[:], src: const u8[:], dst: const u8[:]) {
    var ends: i64[>..] = [];
    var starts: i64[>..] = [];
    var i = 0;
    while i < names.len {
        var j = i;
        while j < names.len && names[j] != '\n' { j++; }
        if j > i { starts.push(i); ends.push(j); }
        i = j + 1;
    }
    var k = starts.len - 1;
    while k >= 0 {
        let name = names[starts[k]..ends[k]];
        let a = if attrs.len > k { attrs[k] } else { ssh::no_attrs() };
        push_job(JOB_COPY, fs::join(src, name), fs::join(dst, name), a);
        k--;
    }
}

// Uploads a local file or (with -r) directory, following links.
fn put_path(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, src0: const u8[:], dst0: const u8[:]) {
    push_job(JOB_COPY, src0, dst0, ssh::no_attrs());
    loop {
        let kind, src, dst, unused, ok = pop_job();
        if !ok || cx.l.gone { break; }
        let st, e = fs::stat(src, true);
        if e < 0 { report(cx.o, str(src, ": ", ssh::sftp_status_text(fs::status(e)))); continue; }
        if kind == JOB_DIR_DONE {
            if cx.l.preserve {
                var a = ssh::no_attrs();
                a.flags = ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME;
                a.perm = st.mode & 0xfff;
                a.atime = st.atime as! u32;
                a.mtime = st.mtime as! u32;
                let sid = new_id();
                var sreq: u8[>..] = [];
                ssh::sftp_setstat(sreq, ssh::FXP_SETSTAT, sid, dst, a);
                let sc, stext = rsimple(cx, cfg, c, out, sreq, sid);
                if sc != ssh::FX_OK { report(cx.o, str(dst, ": set times: ", stext)); }
            }
            continue;
        }
        if fs::is_reg(st) { upload(cx, cfg, c, out, src, st, dst); continue; }
        if !fs::is_dir(st) || !cx.l.deep { report(cx.o, str(src, ": not a regular file")); continue; }
        login::log(cx.o, str("directory ", src, " -> ", dst));
        let id = new_id();
        var req: u8[>..] = [];
        ssh::sftp_mkdir(req, id, dst, ssh::perm_attrs(local_mode(st.mode) | 0x1c0));        // | 0700
        let mc, mt = rsimple(cx, cfg, c, out, req, id);
        if mc != ssh::FX_OK {
            let ra, rc, rt = rstat(cx, cfg, c, out, dst, true);
            if rc != ssh::FX_OK || !ssh::is_dir_attrs(ra) { report(cx.o, str("remote mkdir \"", dst, "\": ", mt)); continue; }
        }
        let slot = fs::fs_opendir(src);
        if slot < 0 { report(cx.o, str(src, ": ", ssh::sftp_status_text(fs::status(slot)))); continue; }
        var names: u8[>..] = [];
        loop {
            let name, n = fs::readdir(slot);
            if n <= 0 { break; }
            if name == "." || name == ".." { continue; }
            names.append(name);
            names.push('\n');
        }
        let x = fs::fs_closedir(slot);
        push_job(JOB_DIR_DONE, src, dst, ssh::no_attrs());
        var none: ssh::Attrs[>..] = [];
        push_entries(names, none, src, dst);
    }
    job_starts.clear();
    jobs.clear();
}

// Downloads a remote file or (with -r) directory; a link is followed.
fn get_path(cx: Ctx&, cfg: ssh::ClientConfig&, c: ssh::Conn&, out: u8[>..]&, src0: const u8[:], a0: ssh::Attrs, dst0: const u8[:]) {
    push_job(JOB_COPY, src0, dst0, a0);
    loop {
        let kind, src, dst, a1, ok = pop_job();
        if !ok || cx.l.gone { break; }
        var a = a1;
        if kind == JOB_DIR_DONE {
            if cx.l.preserve {
                let t = fs::fs_utimes(dst, -1, a.atime, a.mtime, 1);
                let m = fs::fs_chmod(dst, -1, a.perm & 0xfff, 1);
                if t < 0 || m < 0 { report(cx.o, str(dst, ": set times or mode: ", ssh::sftp_status_text(fs::status(::min(t, m))))); }
            }
            continue;
        }
        if ssh::is_link_attrs(a) || (a.flags & ssh::ATTR_PERMISSIONS) == 0 {
            let fa, fc, ft = rstat(cx, cfg, c, out, src, true);
            if fc != ssh::FX_OK { report(cx.o, str(src, ": ", ft)); continue; }
            a = fa;
        }
        if ssh::is_reg_attrs(a) { download(cx, cfg, c, out, src, a, dst); continue; }
        if !ssh::is_dir_attrs(a) || !cx.l.deep { report(cx.o, str(src, ": not a regular file")); continue; }
        login::log(cx.o, str("directory ", src, " -> ", dst));
        let me = fs::fs_mkdir(dst, local_mode(a.perm) | 0x1c0);
        if me < 0 {
            let st, e = fs::stat(dst, true);
            if e < 0 || !fs::is_dir(st) { report(cx.o, str(dst, ": ", ssh::sftp_status_text(fs::status(me)))); continue; }
        }
        var names: u8[>..] = [];
        var attrs: ssh::Attrs[>..] = [];
        if !list_remote(cx, cfg, c, out, src, names, attrs) { continue; }
        push_job(JOB_DIR_DONE, src, dst, a);
        push_entries(names, attrs, src, dst);
    }
    job_starts.clear();
    jobs.clear();
}

// --- Patterns -----------------------------------------------------------------------

// Whether a name matches a pattern of *, ? and [...] (with ! or ^ to
// negate, and ranges), as fnmatch(3) without flags; a leading dot is
// matched only by one.
recursive fn glob_match(p: const u8[:], s: const u8[:]) -> bool {
    if p.len == 0 { return s.len == 0; }
    if p[0] == '*' {
        for i in s.len + 1 { if glob_match(p[1..], s[i..]) { return true; } }
        return false;
    }
    if s.len == 0 { return false; }
    if p[0] == '?' { return glob_match(p[1..], s[1..]); }
    if p[0] == '[' {
        var j = 1;
        let neg = j < p.len && (p[j] == '!' || p[j] == '^');
        if neg { j++; }
        var hit = false;
        var first = true;
        while j < p.len && (first || p[j] != ']') {
            first = false;
            if j + 2 < p.len && p[j + 1] == '-' && p[j + 2] != ']' {
                if s[0] >= p[j] && s[0] <= p[j + 2] { hit = true; }
                j += 3;
            } else {
                if s[0] == p[j] { hit = true; }
                j++;
            }
        }
        if j >= p.len { return s[0] == '[' && glob_match(p[1..], s[1..]); }   // no ]: a plain [
        return hit != neg && glob_match(p[j + 1..], s[1..]);
    }
    if p[0] == '\\' && p.len > 1 { return s[0] == p[1] && glob_match(p[2..], s[1..]); }
    return s[0] == p[0] && glob_match(p[1..], s[1..]);
}

fn has_pattern(s: const u8[:]) -> bool {
    for ch in s { if ch == '*' || ch == '?' || ch == '[' { return true; } }
    return false;
}

// --- Arguments ---------------------------------------------------------------------

// Where a remote argument's path starts (after the colon), or -1 for a
// local one: a colon before any slash, outside [brackets], not first.
fn colon(arg: const u8[:]) -> i64 {
    var depth = 0;
    for i in arg.len {
        let ch = arg[i];
        if ch == '[' { depth++; }
        else if ch == ']' { depth--; }
        else if ch == '/' && depth == 0 { return -1; }
        else if ch == ':' && depth == 0 { return if i == 0 { -1 } else { i }; }
    }
    return -1;
}

fn unbracket(host: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if host.len >= 2 && host[0] == '[' && host[host.len - 1] == ']' { out.append(host[1..host.len - 1]); }
    else { out.append(host); }
    return out;
}

fn usage(o: const login::Options&) -> i32 {
    sysnet::eprint("usage: goose-scp [-r] [-p] [-q] [-v] [-P port] [-i keyfile]... [-o option=value]... [-J jump] source... target\n");
    return 1;
}

fn run() -> i32 {
    sysnet::net_init();
    let a = args();
    var o = login::options("goose-scp");
    var deep = false;
    var preserve = false;
    var paths: u8[:][>..] = [];
    var i = 1;
    var options_done = false;
    while i < a.len {
        let w = a[i];
        if !options_done && w == "--" { options_done = true; i++; continue; }
        if !options_done && w.len > 1 && w[0] == '-' {
            let t = login::take_option(o, a, i, "-P");
            if t < 0 { return usage(o); }
            if t > 0 { continue; }
            // Flags may be grouped: -rp.
            var ok = true;
            for ch in w[1..] {
                if ch == 'r' { deep = true; }
                else if ch == 'p' { preserve = true; }
                else if ch == 'q' { }
                else if ch == 'v' { o.verbose = true; }
                else { ok = false; }
            }
            if !ok { return usage(o); }
            i++;
            continue;
        }
        paths.push(w);
        i++;
    }
    if paths.len < 2 { return usage(o); }
    let target = paths[paths.len - 1];
    let tc = colon(target);
    // The host: the target's, else every source's, which must be one.
    var host_arg: u8[>..] = [];
    var nsrc_remote = 0;
    for k in paths.len - 1 {
        let cpos = colon(paths[k]);
        if cpos < 0 { continue; }
        nsrc_remote++;
        let h = paths[k][..cpos];
        if host_arg.len > 0 && h != host_arg {
            sysnet::eprint("goose-scp: copies from more than one host are not supported\n");
            return 1;
        }
        host_arg.clear();
        host_arg.append(h);
    }
    let upload = tc >= 0;
    if upload && nsrc_remote > 0 { sysnet::eprint("goose-scp: copies between remote hosts are not supported\n"); return 1; }
    if !upload && nsrc_remote == 0 { sysnet::eprint("goose-scp: no remote file: use cp\n"); return 1; }
    if !upload && nsrc_remote != paths.len - 1 {
        sysnet::eprint("goose-scp: the sources must all be remote or all local\n");
        return 1;
    }
    if upload { host_arg.clear(); host_arg.append(target[..tc]); }
    let host = unbracket(login::split_target(o, host_arg));
    var cfg = login::config(o, host);

    login::log(o, str("connecting to ", host, " port ", o.port));
    let t = login::connect(o, host, o.port);
    if t.rfd < 0 { sysnet::eprint(str("goose-scp: cannot connect to ", host, " port ", o.port, "\n")); return 255; }
    var c = ssh::client(cfg);
    var out: u8[>..] = [];
    ssh::client_start(c, cfg, out);
    var cx = Ctx { o: o, l: Link { sock: t.rfd, wsock: t.wfd, ch: -1, ready: false, gone: false, expand: false, preserve: preserve, deep: deep } };

    // The VERSION, which names the server's extensions.
    let vp = next_packet(cx.o, cfg, c, cx.l, out);
    let vm, vok = ssh::sftp_parse(vp);
    if vp.len == 0 || !vok || vm.kind != ssh::FXP_VERSION {
        login::close_transport(t);
        if vp.len > 0 { sysnet::eprint("goose-scp: the server did not answer INIT\n"); }
        return 255;
    }
    let ev, has_expand = ssh::sftp_extension(vp, vm, "expand-path@openssh.com");
    cx.l.expand = has_expand;
    login::log(cx.o, str("sftp version ", vm.id));

    if upload {
        let rp, okp = remote_path(cx, cfg, c, out, target[tc + 1..]);
        if okp {
            let ta, tcode, tt = rstat(cx, cfg, c, out, rp, true);
            let into_dir = tcode == ssh::FX_OK && ssh::is_dir_attrs(ta);
            if paths.len > 2 && !into_dir {
                report(cx.o, str(target[tc + 1..], ": not a directory"));
            } else {
                for k in paths.len - 1 {
                    let src = paths[k];
                    var dst: u8[>..] = [];
                    if into_dir { dst.append(fs::join(rp, fs::base_name(src))); } else { dst.append(rp); }
                    put_path(cx, cfg, c, out, src, dst);
                    if cx.l.gone { break; }
                }
            }
        }
    } else {
        let lt, le = fs::stat(target, true);
        let into_dir = le == 0 && fs::is_dir(lt);
        // Each source, its pattern (in its last part) matched in its directory.
        var total = 0;
        var names: u8[>..] = [];
        var attrs: ssh::Attrs[>..] = [];
        for k in paths.len - 1 {
            let cpos = colon(paths[k]);
            let rp, okp = remote_path(cx, cfg, c, out, paths[k][cpos + 1..]);
            if !okp { continue; }
            let base = fs::base_name(rp);
            if has_pattern(base) {
                var dir: u8[>..] = [];
                dir.append(if base.len == rp.len { "." } else { rp[..rp.len - base.len] });
                var all: u8[>..] = [];
                var aa: ssh::Attrs[>..] = [];
                if !list_remote(cx, cfg, c, out, dir, all, aa) { continue; }
                var j = 0;
                var found = 0;
                for name in split(all, '\n') {
                    if name.len == 0 { continue; }
                    let hidden_ok = name[0] != '.' || base[0] == '.';
                    if hidden_ok && glob_match(base, name) {
                        names.append(fs::join(dir, name));
                        names.push('\n');
                        attrs.push(aa[j]);
                        found++;
                    }
                    j++;
                }
                if found == 0 { report(cx.o, str(paths[k][cpos + 1..], ": No such file or directory")); }
                total += found;
            } else {
                let a2, code, text = rstat(cx, cfg, c, out, rp, true);
                if code != ssh::FX_OK { report(cx.o, str(rp, ": ", text)); continue; }
                names.append(rp);
                names.push('\n');
                attrs.push(a2);
                total++;
            }
            if cx.l.gone { break; }
        }
        if total > 1 && !into_dir {
            report(cx.o, str(target, ": not a directory"));
        } else {
            var j = 0;
            for src in split(names, '\n') {
                if src.len == 0 { continue; }
                var dst: u8[>..] = [];
                if into_dir { dst.append(fs::join(target, fs::base_name(src))); } else { dst.append(target); }
                get_path(cx, cfg, c, out, src, attrs[j], dst);
                j++;
                if cx.l.gone { break; }
            }
        }
    }
    if cx.l.gone && !ssh::closed(c) { errors++; }
    ssh::disconnect(c, out);
    let w = send_all(t.wfd, out);
    login::close_transport(t);
    return if errors > 0 { 1 } else { 0 };
}

fn main() {
    let code = run();
    flush_stdout();
    exit(code);
}
