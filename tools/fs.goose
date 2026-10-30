// The file system for tools/sftp_server.goose and tools/scp.goose: the C
// of tools/fs.c, declared for Goose, with the helpers both use (a file's
// attributes as SFTP's, errno as SFTP's status codes). Every call that can
// fail returns -errno, as fs.c does. A tool's .build sidecar compiles fs.c.
namespace fs;

import std;
import ssh.sftp;

extern fn fs_open(path: const u8[:], pflags: u32, mode: u32) -> i32;
extern fn fs_close(fd: i32) -> i32;
extern fn fs_pread(fd: i32, buf: u8[:], offset: u64) -> i64;
extern fn fs_pwrite(fd: i32, data: const u8[:], offset: u64, append: i32) -> i64;
extern fn fs_stat(path: const u8[:], follow: i32, st: u64[:]) -> i32;
extern fn fs_fstat(fd: i32, st: u64[:]) -> i32;
extern fn fs_truncate(path: const u8[:], fd: i32, size: u64) -> i32;
extern fn fs_chmod(path: const u8[:], fd: i32, mode: u32, follow: i32) -> i32;
extern fn fs_chown(path: const u8[:], fd: i32, uid: u32, gid: u32, follow: i32) -> i32;
extern fn fs_utimes(path: const u8[:], fd: i32, atime: u64, mtime: u64, follow: i32) -> i32;
extern fn fs_fsync(fd: i32) -> i32;
extern fn fs_unlink(path: const u8[:]) -> i32;
extern fn fs_mkdir(path: const u8[:], mode: u32) -> i32;
extern fn fs_rmdir(path: const u8[:]) -> i32;
// kind 0: rename, 1: link, 2: symlink(target, link).
extern fn fs_two(from: const u8[:], to: const u8[:], kind: i32) -> i32;
// kind 0: readlink, 1: realpath.
extern fn fs_resolve(path: const u8[:], out: u8[:], kind: i32) -> i64;
extern fn fs_statvfs(path: const u8[:], fd: i32, out: u64[:]) -> i32;
extern fn fs_opendir(path: const u8[:]) -> i32;
extern fn fs_readdir(slot: i32, out: u8[:]) -> i64;
extern fn fs_closedir(slot: i32) -> i32;
extern fn fs_home(user: const u8[:], out: u8[:]) -> i64;
extern fn fs_id_name(id: u32, kind: i32, out: u8[:]) -> i64;
extern fn fs_umask() -> u32;
extern fn fs_errno(which: i32) -> i32;

// What stat says of a file.
struct Stat { size: u64, uid: u32, gid: u32, mode: u32, atime: u64, mtime: u64, nlink: u64 }

fn no_stat() -> Stat { Stat { size: 0, uid: 0, gid: 0, mode: 0, atime: 0, mtime: 0, nlink: 0 } }

fn to_stat(v: const u64[:]) -> Stat {
    Stat { size: v[0], uid: v[1] as! u32, gid: v[2] as! u32, mode: v[3] as! u32, atime: v[4], mtime: v[5], nlink: v[6] }
}

// stat (follow) or lstat: the file's, and 0 or -errno.
fn stat(path: const u8[:], follow: bool) -> Stat, i64 {
    var v: u64[7] = [0; 7];
    let r = fs_stat(path, if follow { 1 } else { 0 }, v);
    if r < 0 { return no_stat(), r; }
    return to_stat(v), 0;
}

fn fstat(fd: i32) -> Stat, i64 {
    var v: u64[7] = [0; 7];
    let r = fs_fstat(fd, v);
    if r < 0 { return no_stat(), r; }
    return to_stat(v), 0;
}

// A file's attributes as SFTP sends them: size, owner, mode and times.
// Times past 2106 do not fit version 3's 32 bits and are cut.
fn attrs(s: const Stat&) -> ssh::Attrs {
    ssh::Attrs { flags: ssh::ATTR_SIZE | ssh::ATTR_UIDGID | ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME,
                 size: s.size, uid: s.uid, gid: s.gid, perm: s.mode, atime: s.atime as! u32, mtime: s.mtime as! u32 }
}

fn is_dir(s: const Stat&) -> bool { (s.mode & ssh::S_IFMT) == ssh::S_IFDIR }
fn is_reg(s: const Stat&) -> bool { (s.mode & ssh::S_IFMT) == ssh::S_IFREG }

// readlink (kind 0) or realpath (kind 1): the result, and 0 or -errno.
fn resolve(path: const u8[:], kind: i32) -> u8[>..], i64 {
    var buf: u8[4096] = [0; 4096];
    let n = fs_resolve(path, buf, kind);
    var out: u8[>..] = [];
    if n < 0 { return out, n; }
    out.append(buf[..n]);
    return out, 0;
}

// The next name of an open directory: the name and its length; 0 at the
// end, -errno on failure.
fn readdir(slot: i32) -> u8[>..], i64 {
    var buf: u8[1024] = [0; 1024];
    let n = fs_readdir(slot, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); }
    return out, n;
}

// A user's home directory ("" for this process's user); false if unknown.
fn home(user: const u8[:]) -> u8[>..], bool {
    var buf: u8[4096] = [0; 4096];
    let n = fs_home(user, buf);
    var out: u8[>..] = [];
    if n < 0 { return out, false; }
    out.append(buf[..n]);
    return out, true;
}

// A user's (kind 0) or group's (1) name, or the number when it has none.
fn id_name(id: u32, kind: i32) -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = fs_id_name(id, kind, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); } else { format_uint(out, id, 10, 0, ' '); }
    return out;
}

fn err_is(e: i64, which: i32) -> bool { e == -(fs_errno(which) as i64) }

// errno as SFTP's status, as OpenSSH's sftp-server maps it: no such file
// for ENOENT, ENOTDIR, EBADF and ELOOP; permission denied for EPERM,
// EACCES and EFAULT; a bad message for ENAMETOOLONG and EINVAL;
// unsupported for ENOSYS; a failure otherwise.
fn status(e: i64) -> u32 {
    if e >= 0 { return ssh::FX_OK; }
    if err_is(e, 0) || err_is(e, 1) || err_is(e, 2) || err_is(e, 3) { return ssh::FX_NO_SUCH_FILE; }
    if err_is(e, 4) || err_is(e, 5) || err_is(e, 6) { return ssh::FX_PERMISSION_DENIED; }
    if err_is(e, 7) || err_is(e, 8) { return ssh::FX_BAD_MESSAGE; }
    if err_is(e, 9) { return ssh::FX_OP_UNSUPPORTED; }
    return ssh::FX_FAILURE;
}

// A path's last part, and the path joined with a name.
fn base_name(path: const u8[:]) -> const u8[:] {
    var end = path.len;
    while end > 1 && path[end - 1] == '/' { end--; }
    var i = end;
    while i > 0 && path[i - 1] != '/' { i--; }
    return path[i..end];
}

fn join(dir: const u8[:], name: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(dir);
    if out.len > 0 && out[out.len - 1] != '/' { out.push('/'); }
    out.append(name);
    return out;
}
