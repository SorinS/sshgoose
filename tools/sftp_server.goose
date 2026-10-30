// goose-sftp-server: an SFTP server (version 3, ssh.sftp) on stdin and
// stdout, as OpenSSH's sftp-server: goose-sshd runs it for a session's
// "sftp" subsystem, and so can OpenSSH's sshd (Subsystem sftp
// /path/goose-sftp-server); `sftp -D goose-sftp-server` talks to it with no
// SSH at all.
//
//   goose-sftp-server [-e] [-v]
//
// It has the file access of the user running it, relative paths starting
// from its working directory. Its extensions are OpenSSH's:
// posix-rename, statvfs, fstatvfs, hardlink, fsync, lsetstat, limits,
// expand-path, users-groups-by-id (all @openssh.com), copy-data and
// home-directory. -e or -v logs each request to stderr. It ends when stdin
// does, or on a packet longer than SFTP_MAX_PACKET or before INIT.
import std;
import os;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.sftp;
import .sysnet;
import .fs;

var verbose = false;

fn log(s: const u8[:]) { if verbose { sysnet::eprint(str("goose-sftp-server: ", s, "\n")); } }

let MAX_HANDLES: i64 = 64;
let NAMES_PER_READDIR: i64 = 100;      // as OpenSSH's sftp-server

let H_FREE: i64 = 0;
let H_FILE: i64 = 1;
let H_DIR: i64 = 2;

// An open file (fd) or directory (fs.c's slot, and its path, for its
// entries' attributes). A handle on the wire is its index and generation,
// so a closed one never names the slot's next use.
struct Handle { kind: i64, fd: i32, gen: u32, append: bool, path: u8[..4096] }

struct Server { handles: Handle[..64], gen: u32, inited: bool, now: i64 }

fn free_handle() -> Handle { Handle { kind: H_FREE, fd: -1, gen: 0, append: false, path: [] } }

// A new handle's wire form, or "" when all are in use.
fn new_handle(s: Server&, kind: i64, fd: i32, append: bool, path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var slot = -1;
    for i in s.handles.len { if s.handles[i].kind == H_FREE { slot = i; break; } }
    if slot < 0 && s.handles.len < MAX_HANDLES { s.handles.push(free_handle()); slot = s.handles.len - 1; }
    if slot < 0 || path.len > 4096 { return out; }
    s.gen++;
    var h = &s.handles[slot];
    h.kind = kind;
    h.fd = fd;
    h.gen = s.gen;
    h.append = append;
    h.path.clear();
    h.path.append(path);
    ssh::put_u32(out, slot as! u32);
    ssh::put_u32(out, s.gen);
    return out;
}

// The slot a handle names, if it is open and of the kind (H_FREE: either).
fn find_handle(s: const Server&, h: const u8[:], kind: i64) -> i64 {
    if h.len != 8 { return -1; }
    var r = ssh::rd(h);
    let slot: i64 = ssh::get_u32(r, h);
    let gen = ssh::get_u32(r, h);
    if slot >= s.handles.len { return -1; }
    let e = &s.handles[slot];
    if e.kind == H_FREE || e.gen != gen || (kind != H_FREE && e.kind != kind) { return -1; }
    return slot;
}

fn close_handle(s: Server&, slot: i64) -> i64 {
    var h = &s.handles[slot];
    let r: i64 = if h.kind == H_FILE { fs::fs_close(h.fd) } else { fs::fs_closedir(h.fd) };
    h.kind = H_FREE;
    h.fd = -1;
    h.path.clear();
    return r;
}

// SETSTAT's changes, in OpenSSH's order: size, mode, times, owner; the
// first failure stops them. fd >= 0: the open file; follow false: a link
// itself (lsetstat).
fn set_attrs(path: const u8[:], fd: i32, a: ssh::Attrs, follow: bool) -> i64 {
    let fl: i32 = if follow { 1 } else { 0 };
    if (a.flags & ssh::ATTR_SIZE) != 0 {
        let r = fs::fs_truncate(path, fd, a.size);
        if r < 0 { return r; }
    }
    if (a.flags & ssh::ATTR_PERMISSIONS) != 0 {
        let r = fs::fs_chmod(path, fd, a.perm, fl);
        if r < 0 { return r; }
    }
    if (a.flags & ssh::ATTR_ACMODTIME) != 0 {
        let r = fs::fs_utimes(path, fd, a.atime, a.mtime, fl);
        if r < 0 { return r; }
    }
    if (a.flags & ssh::ATTR_UIDGID) != 0 {
        let r = fs::fs_chown(path, fd, a.uid, a.gid, fl);
        if r < 0 { return r; }
    }
    return 0;
}

// RENAME as OpenSSH's sftp-server does it, refusing to replace a file as
// the draft says: a regular file is linked to its new name and then
// unlinked (where the file system has no links, renamed if nothing has
// that name); anything else is renamed if nothing has the name.
fn rename_no_replace(from: const u8[:], to: const u8[:]) -> i64 {
    let st, e = fs::stat(from, false);
    if e < 0 { return e; }
    if fs::is_reg(st) {
        let r = fs::fs_two(from, to, 1);
        if r == 0 {
            let u = fs::fs_unlink(from);
            if u < 0 { let x = fs::fs_unlink(to); return u; }
            return 0;
        }
        // EOPNOTSUPP, ENOSYS, EXDEV, EPERM: no hard links here.
        if !(fs::err_is(r, 14) || fs::err_is(r, 9) || fs::err_is(r, 13) || fs::err_is(r, 4)) { return r; }
    }
    let t, e2 = fs::stat(to, false);
    if e2 == 0 { return -(fs::fs_errno(10) as i64); }      // EEXIST
    return fs::fs_two(from, to, 0);
}

// A path with ~ expanded as OpenSSH's sftp-server does: "~" and "~/x" are
// relative to the working directory (the home directory, under sshd), and
// "~user/x" is in that user's home directory.
fn expand_tilde(path: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if path.len == 0 || path[0] != '~' { out.append(path); return out, true; }
    if path == "~" { out.append("."); return out, true; }
    if path.starts_with("~/") { out.append(path[2..]); return out, true; }
    var slash = 1;
    while slash < path.len && path[slash] != '/' { slash++; }
    let h, ok = fs::home(path[1..slash]);
    if !ok { return out, false; }
    out.append(h);
    out.append(path[slash..]);
    return out, true;
}

fn status(out: u8[>..]&, id: u32, e: i64) { ssh::sftp_status(out, id, fs::status(e)); }

// One NAME entry, for a reply: the name alone (attributes empty), as
// REALPATH, READLINK and expand-path send it.
fn one_name(out: u8[>..]&, id: u32, name: const u8[:]) {
    let mark = ssh::sftp_name_begin(out, id);
    ssh::sftp_name_add(out, name, name, ssh::no_attrs());
    ssh::sftp_name_end(out, mark, 1);
}

// A path made absolute, its links and . and .. resolved. As OpenSSH's
// sftp-server (OpenBSD's realpath), the last part need not exist, so that
// a client can name a file it is about to make: the directory resolved,
// with the name put after it.
fn real_path(path: const u8[:]) -> u8[>..], i64 {
    let p: const u8[:] = if path.len == 0 { "." } else { path };
    let res, e = fs::resolve(p, 1);
    if e == 0 || !fs::err_is(e, 0) { return res, e; }
    var end = p.len;
    while end > 1 && p[end - 1] == '/' { end--; }
    var i = end;
    while i > 0 && p[i - 1] != '/' { i--; }
    let last = p[i..end];
    if last.len == 0 || last == "." || last == ".." { return res, e; }
    let parent: const u8[:] = if i == 0 { "." } else if i == 1 { "/" } else { p[..i - 1] };
    let dir, e2 = fs::resolve(parent, 1);
    if e2 < 0 { return dir, e2; }
    return fs::join(dir, last), 0;
}

fn realpath_reply(out: u8[>..]&, id: u32, path: const u8[:]) {
    let res, e = real_path(path);
    if e < 0 { status(out, id, e); return; }
    one_name(out, id, res);
}

fn version_reply(out: u8[>..]&) {
    let mark = ssh::sftp_version(out);
    let exts: const u8[:][22] = ["posix-rename@openssh.com", "1", "statvfs@openssh.com", "2", "fstatvfs@openssh.com", "2",
                                 "hardlink@openssh.com", "1", "fsync@openssh.com", "1", "lsetstat@openssh.com", "1",
                                 "limits@openssh.com", "1", "expand-path@openssh.com", "1", "copy-data", "1",
                                 "home-directory", "1", "users-groups-by-id@openssh.com", "1"];
    for e in exts { ssh::put_string(out, e); }
    ssh::sftp_end(out, mark);
}

fn statvfs_reply(out: u8[>..]&, id: u32, path: const u8[:], fd: i32) {
    var v: u64[11] = [0; 11];
    let r = fs::fs_statvfs(path, fd, v);
    if r < 0 { status(out, id, r); return; }
    let mark = ssh::sftp_req(out, ssh::FXP_EXTENDED_REPLY, id);
    for x in v { ssh::put_u64(out, x); }
    ssh::sftp_end(out, mark);
}

// READDIR: up to NAMES_PER_READDIR entries with their lstat attributes and
// ls -l longnames (an entry that vanished meanwhile is left out); EOF once
// there are no more.
fn readdir_reply(s: Server&, out: u8[>..]&, id: u32, slot: i64) {
    let mark = ssh::sftp_name_begin(out, id);
    var count: u32 = 0;
    let dir = s.handles[slot].path;
    while count < NAMES_PER_READDIR {
        let name, n = fs::readdir(s.handles[slot].fd);
        if n < 0 {
            if count > 0 { break; }
            out.resize(mark, 0);
            status(out, id, n);
            return;
        }
        if n == 0 { break; }
        let st, e = fs::stat(fs::join(dir, name), false);
        if e < 0 { continue; }
        var long: u8[>..] = [];
        ssh::sftp_longname(long, name, fs::attrs(st), st.nlink, fs::id_name(st.uid, 0), fs::id_name(st.gid, 1), s.now);
        ssh::sftp_name_add(out, name, long, fs::attrs(st));
        count++;
    }
    if count == 0 {
        out.resize(mark, 0);
        ssh::sftp_status(out, id, ssh::FX_EOF);
        return;
    }
    ssh::sftp_name_end(out, mark, count);
}

// copy-data: the read handle's bytes from roff (rlen of them, or to its end
// for 0) written to the write handle at woff; 0 or -errno.
fn copy_data(s: const Server&, rs: i64, roff: u64, rlen: u64, ws: i64, woff: u64) -> i64 {
    var buf: u8[>..] = [];
    buf.resize(65536, 0);
    var done: u64 = 0;
    loop {
        var want: u64 = 65536;
        if rlen != 0 && rlen - done < want { want = rlen - done; }
        if want == 0 { break; }
        let n = fs::fs_pread(s.handles[rs].fd, buf[..want as! i64], roff + done);
        if n < 0 { return n; }
        if n == 0 { break; }
        let w = fs::fs_pwrite(s.handles[ws].fd, buf[..n], woff + done, if s.handles[ws].append { 1 } else { 0 });
        if w < 0 { return w; }
        done += n as! u64;
    }
    // Fewer bytes than asked for, the file being shorter: a success, as
    // OpenSSH's.
    return 0;
}

// users-groups-by-id: a string of uint32 uids and one of gids; the reply
// a string of their names (each a string, "" for an unknown one), then the
// same for the groups.
fn names_by_id(out: u8[>..]&, m: const u8[:], ids: ssh::Rd, kind: i32) {
    var names: u8[>..] = [];
    var r = ids;
    while r.pos + 4 <= r.end {
        let id = ssh::get_u32(r, m);
        var buf: u8[256] = [0; 256];
        let n = fs::fs_id_name(id, kind, buf);
        ssh::put_string(names, buf[..::max(n, 0)]);
    }
    ssh::put_string(out, names);
}

fn extended(s: Server&, out: u8[>..]&, m: const u8[:], id: u32, r: ssh::Rd&) {
    let name = ssh::get_string(r, m);
    let n = ssh::bytes(m, name);
    log(str("extended ", n));
    if n == "posix-rename@openssh.com" || n == "hardlink@openssh.com" {
        let a = ssh::get_string(r, m);
        let b = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        status(out, id, fs::fs_two(ssh::bytes(m, a), ssh::bytes(m, b), if n == "posix-rename@openssh.com" { 0 } else { 1 }));
    } else if n == "statvfs@openssh.com" {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        statvfs_reply(out, id, ssh::bytes(m, p), -1);
    } else if n == "fstatvfs@openssh.com" || n == "fsync@openssh.com" {
        let h = ssh::get_string(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FILE);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        if n == "fsync@openssh.com" { status(out, id, fs::fs_fsync(s.handles[slot].fd)); }
        else { statvfs_reply(out, id, "", s.handles[slot].fd); }
    } else if n == "lsetstat@openssh.com" {
        let p = ssh::get_string(r, m);
        let a = ssh::get_attrs(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        status(out, id, set_attrs(ssh::bytes(m, p), -1, a, false));
    } else if n == "limits@openssh.com" {
        let mark = ssh::sftp_req(out, ssh::FXP_EXTENDED_REPLY, id);
        ssh::put_u64(out, ssh::SFTP_MAX_PACKET as! u64);
        ssh::put_u64(out, ssh::SFTP_MAX_DATA as! u64);
        ssh::put_u64(out, ssh::SFTP_MAX_DATA as! u64);
        ssh::put_u64(out, MAX_HANDLES as! u64);
        ssh::sftp_end(out, mark);
    } else if n == "expand-path@openssh.com" {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let x, ok = expand_tilde(ssh::bytes(m, p));
        if !ok { ssh::sftp_status_message(out, id, ssh::FX_NO_SUCH_FILE, "no such user"); return; }
        realpath_reply(out, id, x);
    } else if n == "home-directory" {
        let u = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let h, ok = fs::home(ssh::bytes(m, u));
        if !ok { ssh::sftp_status(out, id, ssh::FX_NO_SUCH_FILE); return; }
        one_name(out, id, h);
    } else if n == "copy-data" {
        let rh = ssh::get_string(r, m);
        let roff = ssh::get_u64(r, m);
        let rlen = ssh::get_u64(r, m);
        let wh = ssh::get_string(r, m);
        let woff = ssh::get_u64(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let rs = find_handle(s, ssh::bytes(m, rh), H_FILE);
        let ws = find_handle(s, ssh::bytes(m, wh), H_FILE);
        if rs < 0 || ws < 0 { ssh::sftp_status(out, id, ssh::FX_FAILURE); return; }
        status(out, id, copy_data(s, rs, roff, rlen, ws, woff));
    } else if n == "users-groups-by-id@openssh.com" {
        let uids = ssh::get_string(r, m);
        let gids = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let mark = ssh::sftp_req(out, ssh::FXP_EXTENDED_REPLY, id);
        names_by_id(out, m, uids, 0);
        names_by_id(out, m, gids, 1);
        ssh::sftp_end(out, mark);
    } else {
        ssh::sftp_status(out, id, ssh::FX_OP_UNSUPPORTED);
    }
}

// One request, its reply appended to out.
fn request(s: Server&, m: const u8[:], msg: const ssh::SftpMsg&, out: u8[>..]&) {
    let id = msg.id;
    var r = msg.body;
    let k = msg.kind;
    if k == ssh::FXP_OPEN {
        let p = ssh::get_string(r, m);
        let pflags = ssh::get_u32(r, m);
        let a = ssh::get_attrs(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let mode: u32 = if (a.flags & ssh::ATTR_PERMISSIONS) != 0 { a.perm } else { 0x1b6 };   // 0666
        log(str("open ", ssh::bytes(m, p), " flags ", pflags));
        let fd = fs::fs_open(ssh::bytes(m, p), pflags, mode);
        if fd < 0 { status(out, id, fd); return; }
        let h = new_handle(s, H_FILE, fd, (pflags & ssh::FXF_APPEND) != 0, "");
        if h.len == 0 { let x = fs::fs_close(fd); ssh::sftp_status(out, id, ssh::FX_FAILURE); return; }
        ssh::sftp_handle(out, id, h);
    } else if k == ssh::FXP_CLOSE {
        let h = ssh::get_string(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FREE);
        // A handle not open: no such file, as OpenSSH's has it for CLOSE
        // (and a failure for the other requests).
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_NO_SUCH_FILE }); return; }
        status(out, id, close_handle(s, slot));
    } else if k == ssh::FXP_READ {
        let h = ssh::get_string(r, m);
        let off = ssh::get_u64(r, m);
        let len: i64 = ssh::get_u32(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FILE);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        var buf: u8[>..] = [];
        buf.resize(::min(len, ssh::SFTP_MAX_DATA), 0);
        let n = fs::fs_pread(s.handles[slot].fd, buf, off);
        if n < 0 { status(out, id, n); return; }
        if n == 0 && buf.len > 0 { ssh::sftp_status(out, id, ssh::FX_EOF); return; }
        ssh::sftp_data(out, id, buf[..n]);
    } else if k == ssh::FXP_WRITE {
        let h = ssh::get_string(r, m);
        let off = ssh::get_u64(r, m);
        let d = ssh::get_string(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FILE);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        status(out, id, fs::fs_pwrite(s.handles[slot].fd, ssh::bytes(m, d), off, if s.handles[slot].append { 1 } else { 0 }));
    } else if k == ssh::FXP_LSTAT || k == ssh::FXP_STAT {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let st, e = fs::stat(ssh::bytes(m, p), k == ssh::FXP_STAT);
        if e < 0 { status(out, id, e); return; }
        ssh::sftp_attrs(out, id, fs::attrs(st));
    } else if k == ssh::FXP_FSTAT {
        let h = ssh::get_string(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FILE);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        let st, e = fs::fstat(s.handles[slot].fd);
        if e < 0 { status(out, id, e); return; }
        ssh::sftp_attrs(out, id, fs::attrs(st));
    } else if k == ssh::FXP_SETSTAT {
        let p = ssh::get_string(r, m);
        let a = ssh::get_attrs(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        status(out, id, set_attrs(ssh::bytes(m, p), -1, a, true));
    } else if k == ssh::FXP_FSETSTAT {
        let h = ssh::get_string(r, m);
        let a = ssh::get_attrs(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_FILE);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        status(out, id, set_attrs("", s.handles[slot].fd, a, true));
    } else if k == ssh::FXP_OPENDIR {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        log(str("opendir ", ssh::bytes(m, p)));
        let slot = fs::fs_opendir(ssh::bytes(m, p));
        if slot < 0 { status(out, id, slot); return; }
        let h = new_handle(s, H_DIR, slot, false, ssh::bytes(m, p));
        if h.len == 0 { let x = fs::fs_closedir(slot); ssh::sftp_status(out, id, ssh::FX_FAILURE); return; }
        ssh::sftp_handle(out, id, h);
    } else if k == ssh::FXP_READDIR {
        let h = ssh::get_string(r, m);
        let slot = find_handle(s, ssh::bytes(m, h), H_DIR);
        if r.bad || slot < 0 { ssh::sftp_status(out, id, if r.bad { ssh::FX_BAD_MESSAGE } else { ssh::FX_FAILURE }); return; }
        readdir_reply(s, out, id, slot);
    } else if k == ssh::FXP_REMOVE || k == ssh::FXP_RMDIR {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        log(str(if k == ssh::FXP_REMOVE { "remove " } else { "rmdir " }, ssh::bytes(m, p)));
        status(out, id, if k == ssh::FXP_REMOVE { fs::fs_unlink(ssh::bytes(m, p)) } else { fs::fs_rmdir(ssh::bytes(m, p)) });
    } else if k == ssh::FXP_MKDIR {
        let p = ssh::get_string(r, m);
        let a = ssh::get_attrs(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let mode: u32 = if (a.flags & ssh::ATTR_PERMISSIONS) != 0 { a.perm } else { 0x1ff };  // 0777
        log(str("mkdir ", ssh::bytes(m, p)));
        status(out, id, fs::fs_mkdir(ssh::bytes(m, p), mode));
    } else if k == ssh::FXP_REALPATH {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        realpath_reply(out, id, ssh::bytes(m, p));
    } else if k == ssh::FXP_RENAME {
        let a = ssh::get_string(r, m);
        let b = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        log(str("rename ", ssh::bytes(m, a), " ", ssh::bytes(m, b)));
        status(out, id, rename_no_replace(ssh::bytes(m, a), ssh::bytes(m, b)));
    } else if k == ssh::FXP_READLINK {
        let p = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        let t, e = fs::resolve(ssh::bytes(m, p), 0);
        if e < 0 { status(out, id, e); return; }
        one_name(out, id, t);
    } else if k == ssh::FXP_SYMLINK {
        // OpenSSH's order: the target, then the link.
        let target = ssh::get_string(r, m);
        let link = ssh::get_string(r, m);
        if r.bad { ssh::sftp_status(out, id, ssh::FX_BAD_MESSAGE); return; }
        status(out, id, fs::fs_two(ssh::bytes(m, target), ssh::bytes(m, link), 2));
    } else if k == ssh::FXP_EXTENDED {
        extended(s, out, m, id, r);
    } else {
        ssh::sftp_status(out, id, ssh::FX_OP_UNSUPPORTED);
    }
}

fn main() {
    sysnet::net_init();
    let a = args();
    for i in 1..a.len {
        // OpenSSH's sftp-server takes -e and -l level; -f and others are
        // taken and ignored too, so that a Subsystem line written for it works.
        if a[i] == "-e" || a[i] == "-v" { verbose = true; }
    }
    var s = Server { handles: [], gen: 0, inited: false, now: 0 };
    var input: u8[>..] = [];
    var out: u8[>..] = [];
    var code = 0;
    loop {
        let n = sysnet::read_some(0, input);
        if n <= 0 { break; }
        var pos = 0;
        var stop = false;
        loop {
            let len = ssh::sftp_packet_len(input[pos..]);
            if len == 0 { break; }
            if len < 0 { log("a packet too long or empty"); stop = true; code = 1; break; }
            let pkt = input[pos..pos + len];
            let msg, ok = ssh::sftp_parse(pkt);
            pos += len;
            if !ok { log("a packet too short"); stop = true; code = 1; break; }
            if !s.inited {
                if msg.kind != ssh::FXP_INIT { log("a request before INIT"); stop = true; code = 1; break; }
                log(str("init, client version ", msg.id));
                s.inited = true;
                version_reply(out);
                continue;
            }
            if msg.kind == ssh::FXP_INIT { log("a second INIT"); stop = true; code = 1; break; }
            s.now = time_ns() / 1000000000;
            request(s, pkt, msg, out);
        }
        if out.len > 0 {
            if sysnet::net_write(1, out) < 0 { break; }
            out.clear();
        }
        if stop { break; }
        var rest: u8[>..] = [];
        rest.append(input[pos..]);
        input.clear();
        input.append(rest);
    }
    for i in s.handles.len { if s.handles[i].kind != H_FREE { let x = close_handle(s, i); } }
    exit(code);
}
