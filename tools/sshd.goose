// goose-sshd: an SSH server on this package, for logging in as the user
// running it:
//
//   goose-sshd [-p port] [-a address] [-h host_key_file]... [-k authorized_keys]
//              [-P password_file] [-u user] [-b banner] [-v]
//
// It listens on 127.0.0.1:2222 by default (-a 0.0.0.0 for every address),
// with the host keys given (by default ./goose_host_ed25519_key, made on
// first start in OpenSSH's format), and lets in the user running it (-u
// names who may log in, though commands still run as this user) with a key
// of the authorized_keys file (by default ~/.ssh/authorized_keys) or a
// password of the password file ("user:password" lines, the password plain
// or a bcrypt hash). Each connection runs in its own process. A session
// runs a command (exec) or the user's shell (shell), on a pseudo-terminal
// when the client asks for one (pty-req, then window-change), with the
// environment the client sends (env), and ends with the exit status.
import std;
import os;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import ssh.conn;
import .sysnet;

var verbose = false;

fn log(s: const u8[:]) { if verbose { sysnet::eprint(str("goose-sshd: ", s, "\n")); } }

fn usage() {
    sysnet::eprint("usage: goose-sshd [-p port] [-a address] [-h host_key_file]... [-k authorized_keys] [-P password_file] [-u user] [-b banner] [-v]\n");
    exit(1);
}

// A host key from its file, or a new Ed25519 one written there.
fn host_key(path: const u8[:]) -> ssh::PrivateKey {
    var text: u8[>..] = [];
    if read_file(path, text) {
        let k, e = ssh::parse_private_key(text);
        if e != ssh::KEY_OK {
            sysnet::eprint(str("goose-sshd: ", path, ": not a usable host key\n"));
            exit(1);
        }
        return k;
    }
    var k = ssh::generate_key(x509::KEY_ED25519);
    k.comment.append("goose-sshd host key");
    if !write_file(path, ssh::marshal_private_key(k)) {
        sysnet::eprint(str("goose-sshd: cannot write ", path, "\n"));
        exit(1);
    }
    let w = write_file(str(path, ".pub"), ssh::marshal_authorized_key(k.public, "goose-sshd host key"));
    sysnet::eprint(str("goose-sshd: made a host key, ", path, "\n"));
    return k;
}

// The one session of a connection: its channel, the child running in it
// (on pipes, or a pty's master), what the client asked for, and output the
// channel's window has not taken yet.
struct Session {
    ch: i64, pid: i32, in_fd: i32, out_fd: i32, err_fd: i32, master: i32,
    want_pty: bool, term: u8[..64], cols: i32, rows: i32, env: u8[..4096],
    out_eof: bool, err_eof: bool, exited: bool, status: i32, finished: bool,
    pending: u8[..65536], pending_err: u8[..65536],
}

fn no_session() -> Session {
    Session { ch: -1, pid: -1, in_fd: -1, out_fd: -1, err_fd: -1, master: -1, want_pty: false, term: [], cols: 80, rows: 24,
              env: [], out_eof: true, err_eof: true, exited: false, status: 0, finished: false, pending: [], pending_err: [] }
}

fn send_all(sock: i32, out: u8[>..]&) -> bool {
    if out.len == 0 { return true; }
    let n = sysnet::net_write(sock, out);
    out.clear();
    return n >= 0;
}

// Starts the session's command ("" for the shell).
fn spawn(s: Session&, cmd: const u8[:]) -> bool {
    if s.want_pty {
        var m: i32 = -1;
        s.pid = sysnet::proc_spawn_pty(cmd, s.env, s.term, s.cols, s.rows, m);
        s.master = m;
        s.out_fd = m;
        s.in_fd = m;
        s.out_eof = false;
        s.err_eof = true;
    } else {
        var i: i32 = -1;
        var o: i32 = -1;
        var e: i32 = -1;
        s.pid = sysnet::proc_spawn(cmd, s.env, i, o, e);
        s.in_fd = i;
        s.out_fd = o;
        s.err_fd = e;
        s.out_eof = false;
        s.err_eof = false;
    }
    return s.pid > 0;
}

fn handle_connection(sock: i32, cfg: const ssh::ServerConfig&, peer: const u8[:]) {
    var c = ssh::server(cfg);
    var out: u8[>..] = [];
    ssh::server_start(c, cfg, out);
    if !send_all(sock, out) { return; }
    var s = no_session();
    var input: u8[>..] = [];
    loop {
        let watch_out = s.pid > 0 && !s.out_eof && s.pending.len == 0;
        let watch_err = s.pid > 0 && !s.err_eof && s.pending_err.len == 0;
        let ready = sysnet::net_poll(sock, if watch_out { s.out_fd } else { -1 }, if watch_err { s.err_fd } else { -1 }, -1, 200);
        var events: u8[>..] = [];
        if (ready & 1) != 0 {
            input.clear();
            let n = sysnet::read_some(sock, input);
            if n <= 0 { break; }
            let r = ssh::server_feed(c, cfg, input, out, events);
        }
        if (ready & 2) != 0 {
            var data: u8[>..] = [];
            let n = sysnet::read_some(s.out_fd, data);
            if n <= 0 { s.out_eof = true; } else { s.pending.append(data[..::min(data.len, s.pending.cap)]); }
        }
        if (ready & 4) != 0 {
            var data: u8[>..] = [];
            let n = sysnet::read_some(s.err_fd, data);
            if n <= 0 { s.err_eof = true; } else { s.pending_err.append(data[..::min(data.len, s.pending_err.cap)]); }
        }
        var pos = 0;
        loop {
            let e, ok = ssh::next_event(events, pos);
            if !ok { break; }
            var r = e.data;
            if e.kind == ssh::EV_AUTHENTICATED {
                log(str("accepted ", ssh::bytes(events, e.data), " from ", peer));
            } else if e.kind == ssh::EV_CHANNEL_OPEN {
                let kind = ssh::get_string(r, events);
                if ssh::bytes(events, kind) == "session" && s.ch < 0 {
                    let a = ssh::channel_accept(c, e.channel, out);
                    s.ch = e.channel;
                } else {
                    let a = ssh::channel_reject(c, e.channel, ssh::OPEN_ADMINISTRATIVELY_PROHIBITED, "one session at a time", out);
                }
            } else if e.kind == ssh::EV_REQUEST && e.channel == s.ch {
                let kind = ssh::get_string(r, events);
                let k = ssh::bytes(events, kind);
                var ok2 = false;
                if k == "pty-req" && s.pid < 0 {
                    let term = ssh::get_string(r, events);
                    let cols = ssh::get_u32(r, events);
                    let rows = ssh::get_u32(r, events);
                    if !r.bad && term.end - term.pos <= 64 {
                        s.want_pty = true;
                        s.term.clear();
                        s.term.append(ssh::bytes(events, term));
                        s.cols = if cols > 0 && cols < 10000 { cols as! i32 } else { 80 };
                        s.rows = if rows > 0 && rows < 10000 { rows as! i32 } else { 24 };
                        ok2 = true;
                    }
                } else if k == "env" {
                    let name = ssh::get_string(r, events);
                    let value = ssh::get_string(r, events);
                    let nm = ssh::bytes(events, name);
                    // NAME=VALUE, one per line: no newlines or '=' in names.
                    var clean = !r.bad && nm.len > 0 && s.env.len + nm.len + value.end - value.pos + 2 <= s.env.cap;
                    for ch in nm { if ch == '=' || ch == '\n' { clean = false; } }
                    for ch in ssh::bytes(events, value) { if ch == '\n' { clean = false; } }
                    if clean {
                        s.env.append(nm);
                        s.env.push('=');
                        s.env.append(ssh::bytes(events, value));
                        s.env.push('\n');
                        ok2 = true;
                    }
                } else if (k == "exec" || k == "shell") && s.pid < 0 {
                    var cmd: u8[>..] = [];
                    if k == "exec" {
                        let cs = ssh::get_string(r, events);
                        if !r.bad { cmd.append(ssh::bytes(events, cs)); }
                    }
                    let what: u8[>..] = if k == "exec" { str("exec ", cmd) } else { "shell" };
                    let how: u8[>..] = if s.want_pty { " on a pty" } else { "" };
                    log(str(what, how));
                    ok2 = spawn(s, cmd);
                } else if k == "window-change" && s.master >= 0 {
                    let cols = ssh::get_u32(r, events);
                    let rows = ssh::get_u32(r, events);
                    if !r.bad { sysnet::proc_resize(s.master, cols as! i32, rows as! i32); }
                    ok2 = true;
                } else if k == "signal" && s.pid > 0 {
                    let name = ssh::get_string(r, events);
                    let n = ssh::bytes(events, name);
                    let sig: i32 = if n == "INT" { 2 } else if n == "HUP" { 1 } else if n == "KILL" { 9 } else if n == "QUIT" { 3 } else { 15 };
                    sysnet::proc_kill(s.pid, sig);
                    ok2 = true;
                }
                if e.value == 1 { let rr = ssh::channel_reply(c, e.channel, ok2, out); }
            } else if e.kind == ssh::EV_DATA && e.channel == s.ch && s.in_fd >= 0 {
                let w = sysnet::net_write(s.in_fd, ssh::bytes(events, e.data));
            } else if e.kind == ssh::EV_EOF && e.channel == s.ch {
                // A pipe's stdin closes; a pty's stays (the shell reads ^D).
                if s.master < 0 && s.in_fd >= 0 {
                    sysnet::net_close(s.in_fd);
                    s.in_fd = -1;
                }
            } else if e.kind == ssh::EV_CLOSE && e.channel == s.ch {
                if s.pid > 0 && !s.exited { sysnet::proc_kill(s.pid, 1); }
                s.finished = true;
            }
        }
        // The child's output into the channel, as its window allows.
        if s.ch >= 0 && ssh::connected(c) {
            if s.pending.len > 0 {
                let n = ssh::channel_send(c, s.ch, s.pending, out);
                var rest: u8[..65536] = [];
                rest.append(s.pending[n..]);
                s.pending = rest;
            }
            if s.pending_err.len > 0 {
                let n = ssh::channel_send_stderr(c, s.ch, s.pending_err, out);
                var rest: u8[..65536] = [];
                rest.append(s.pending_err[n..]);
                s.pending_err = rest;
            }
            // Done: the output read and sent, the child gone.
            if s.pid > 0 && !s.exited && s.out_eof && s.err_eof {
                s.status = sysnet::proc_wait(s.pid, 1);
                s.exited = true;
            }
            if s.exited && !s.finished && s.pending.len == 0 && s.pending_err.len == 0 {
                log(str("exit status ", s.status));
                let x = ssh::exit_status(c, s.ch, s.status as! u32, out);
                ssh::channel_eof(c, s.ch, out);
                ssh::channel_close(c, s.ch, out);
                s.finished = true;
            }
        }
        // A finished session frees its channel for another.
        if s.finished && (s.exited || s.pid < 0) {
            if s.in_fd >= 0 && s.master < 0 { sysnet::net_close(s.in_fd); }
            if s.out_fd >= 0 { sysnet::net_close(s.out_fd); }
            if s.err_fd >= 0 { sysnet::net_close(s.err_fd); }
            s = no_session();
        }
        if !send_all(sock, out) { break; }
        if ssh::closed(c) {
            if ssh::failed(c) { log(str("connection from ", peer, " failed: ", c.message)); }
            break;
        }
    }
    if s.pid > 0 && !s.exited {
        sysnet::proc_kill(s.pid, 1);
        let st = sysnet::proc_wait(s.pid, 1);
    }
    sysnet::net_close(sock);
}

fn main() {
    sysnet::net_init();
    let a = args();
    var port = 2222;
    var addr: u8[>..] = [];
    addr.append("127.0.0.1");
    var keyfiles: u8[>..] = [];
    var authorized: u8[>..] = [];
    var passwords: u8[>..] = [];
    var user = sysnet::user_name();
    var banner: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        if w == "-v" { verbose = true; i++; continue; }
        if i + 1 >= a.len { usage(); }
        if w == "-p" {
            let v, ok = parse_int(a[i + 1], 10);
            if !ok || v <= 0 || v > 65535 { usage(); }
            port = v;
        } else if w == "-a" { addr.clear(); addr.append(a[i + 1]); }
        else if w == "-h" { keyfiles.append(a[i + 1]); keyfiles.push('\n'); }
        else if w == "-k" { authorized.clear(); authorized.append(a[i + 1]); }
        else if w == "-P" { passwords.clear(); passwords.append(a[i + 1]); }
        else if w == "-u" { user.clear(); user.append(a[i + 1]); }
        else if w == "-b" { banner.clear(); banner.append(a[i + 1]); }
        else { usage(); }
        i += 2;
    }
    var cfg = ssh::server_config();
    if keyfiles.len == 0 { keyfiles.append("goose_host_ed25519_key\n"); }
    for path in split(keyfiles, '\n') {
        if path.len == 0 { continue; }
        let k = host_key(path);
        sysnet::eprint(str("goose-sshd: host key ", ssh::key_type(k.key.kind), " ", ssh::fingerprint_sha256(k.public), "\n"));
        let ok = ssh::add_host_key(cfg, k);
    }
    if authorized.len == 0 { authorized.append(str(sysnet::home_dir(), "/.ssh/authorized_keys")); }
    var text: u8[>..] = [];
    if read_file(authorized, text) { cfg.authorized_keys.append(text[..::min(text.len, cfg.authorized_keys.cap)]); }
    if passwords.len > 0 {
        var pw: u8[>..] = [];
        if !read_file(passwords, pw) { sysnet::eprint(str("goose-sshd: cannot read ", passwords, "\n")); exit(1); }
        cfg.passwords.append(pw[..::min(pw.len, cfg.passwords.cap)]);
    }
    if cfg.authorized_keys.len == 0 && cfg.passwords.len == 0 {
        sysnet::eprint("goose-sshd: no authorized keys or passwords: nobody could log in\n");
        exit(1);
    }
    cfg.auth_user.append(user);
    if banner.len > 0 { cfg.banner.append(banner); cfg.banner.push('\n'); }
    let lfd = sysnet::net_listen(addr, port as! i32);
    if lfd < 0 { sysnet::eprint(str("goose-sshd: cannot listen on ", addr, " port ", port, "\n")); exit(1); }
    sysnet::eprint(str("goose-sshd: listening on ", addr, " port ", port, " for ", user, "\n"));
    loop {
        var peer: u8[64] = [0; 64];
        var plen: i64 = 0;
        let fd = sysnet::net_accept(lfd, peer, plen);
        sysnet::proc_reap();
        if fd < 0 { continue; }
        log(str("connection from ", peer[..plen]));
        let pid = sysnet::proc_fork();
        if pid == 0 {
            sysnet::net_close(lfd);
            handle_connection(fd, cfg, peer[..plen]);
            sysnet::proc_exit(0);
        }
        sysnet::net_close(fd);
    }
}
