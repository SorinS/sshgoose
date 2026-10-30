// ssh.sftp: the SSH File Transfer Protocol, version 3
// (draft-ietf-secsh-filexfer-02), as OpenSSH speaks it, with its
// extensions, carried on a session channel's "sftp" subsystem. Without
// I/O: packets are written into builders and read back from whole
// packets, for either side.
//
//   ssh::sftp_init(out);                                   // client
//   let n = ssh::sftp_packet_len(input);                   // > 0: a whole packet
//   let m, ok = ssh::sftp_parse(input[..n]);               // m.kind, m.id, m.body
//   ssh::sftp_open(out, id, "file", ssh::FXF_READ, ssh::no_attrs());
//
// Where OpenSSH departs from the draft, this follows OpenSSH: SYMLINK's
// arguments are the target, then the link (§6.10 has them the other way).
// A packet longer than SFTP_MAX_PACKET is refused, as OpenSSH refuses one.

namespace ssh;

import std;
import ssh;

let SFTP_VERSION: u32 = 3;
let SFTP_MAX_PACKET: i64 = 262144;     // a packet's bytes after its length field, at most (OpenSSH's SFTP_MAX_MSG_LENGTH)
let SFTP_MAX_DATA: i64 = 261120;       // a READ's or WRITE's data, at most (OpenSSH's max-read-length)

// Packet types (§3).
let FXP_INIT: u8 = 1;
let FXP_VERSION: u8 = 2;
let FXP_OPEN: u8 = 3;
let FXP_CLOSE: u8 = 4;
let FXP_READ: u8 = 5;
let FXP_WRITE: u8 = 6;
let FXP_LSTAT: u8 = 7;
let FXP_FSTAT: u8 = 8;
let FXP_SETSTAT: u8 = 9;
let FXP_FSETSTAT: u8 = 10;
let FXP_OPENDIR: u8 = 11;
let FXP_READDIR: u8 = 12;
let FXP_REMOVE: u8 = 13;
let FXP_MKDIR: u8 = 14;
let FXP_RMDIR: u8 = 15;
let FXP_REALPATH: u8 = 16;
let FXP_STAT: u8 = 17;
let FXP_RENAME: u8 = 18;
let FXP_READLINK: u8 = 19;
let FXP_SYMLINK: u8 = 20;
let FXP_STATUS: u8 = 101;
let FXP_HANDLE: u8 = 102;
let FXP_DATA: u8 = 103;
let FXP_NAME: u8 = 104;
let FXP_ATTRS: u8 = 105;
let FXP_EXTENDED: u8 = 200;
let FXP_EXTENDED_REPLY: u8 = 201;

// OPEN's pflags (§6.3).
let FXF_READ: u32 = 0x01;
let FXF_WRITE: u32 = 0x02;
let FXF_APPEND: u32 = 0x04;
let FXF_CREAT: u32 = 0x08;
let FXF_TRUNC: u32 = 0x10;
let FXF_EXCL: u32 = 0x20;

// Which of an ATTRS' fields are there (§5).
let ATTR_SIZE: u32 = 0x01;
let ATTR_UIDGID: u32 = 0x02;
let ATTR_PERMISSIONS: u32 = 0x04;
let ATTR_ACMODTIME: u32 = 0x08;
let ATTR_EXTENDED: u32 = 0x80000000;

// STATUS codes (§7).
let FX_OK: u32 = 0;
let FX_EOF: u32 = 1;
let FX_NO_SUCH_FILE: u32 = 2;
let FX_PERMISSION_DENIED: u32 = 3;
let FX_FAILURE: u32 = 4;
let FX_BAD_MESSAGE: u32 = 5;
let FX_NO_CONNECTION: u32 = 6;
let FX_CONNECTION_LOST: u32 = 7;
let FX_OP_UNSUPPORTED: u32 = 8;

// The permission bits' file types (POSIX's S_IF*), as they arrive in perm.
let S_IFMT: u32 = 0xf000;
let S_IFDIR: u32 = 0x4000;
let S_IFREG: u32 = 0x8000;
let S_IFLNK: u32 = 0xa000;

// A file's attributes: the fields `flags` says are there. Extended pairs
// are read past, never kept.
struct Attrs { flags: u32, size: u64, uid: u32, gid: u32, perm: u32, atime: u32, mtime: u32 }

fn no_attrs() -> Attrs { Attrs { flags: 0, size: 0, uid: 0, gid: 0, perm: 0, atime: 0, mtime: 0 } }

fn perm_attrs(perm: u32) -> Attrs {
    var a = no_attrs();
    a.flags = ATTR_PERMISSIONS;
    a.perm = perm;
    return a;
}

fn is_dir_attrs(a: Attrs) -> bool { (a.flags & ATTR_PERMISSIONS) != 0 && (a.perm & S_IFMT) == S_IFDIR }
fn is_reg_attrs(a: Attrs) -> bool { (a.flags & ATTR_PERMISSIONS) != 0 && (a.perm & S_IFMT) == S_IFREG }
fn is_link_attrs(a: Attrs) -> bool { (a.flags & ATTR_PERMISSIONS) != 0 && (a.perm & S_IFMT) == S_IFLNK }

fn put_attrs(out: u8[>..]&, a: Attrs) {
    let flags = a.flags & (ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME);
    put_u32(out, flags);
    if (flags & ATTR_SIZE) != 0 { put_u64(out, a.size); }
    if (flags & ATTR_UIDGID) != 0 { put_u32(out, a.uid); put_u32(out, a.gid); }
    if (flags & ATTR_PERMISSIONS) != 0 { put_u32(out, a.perm); }
    if (flags & ATTR_ACMODTIME) != 0 { put_u32(out, a.atime); put_u32(out, a.mtime); }
}

// An ATTRS; r.bad if it overruns. Extended pairs are read and dropped,
// and so is the flag.
fn get_attrs(r: Rd&, m: const u8[:]) -> Attrs {
    var a = no_attrs();
    let flags = get_u32(r, m);
    if (flags & ATTR_SIZE) != 0 { a.size = get_u64(r, m); }
    if (flags & ATTR_UIDGID) != 0 { a.uid = get_u32(r, m); a.gid = get_u32(r, m); }
    if (flags & ATTR_PERMISSIONS) != 0 { a.perm = get_u32(r, m); }
    if (flags & ATTR_ACMODTIME) != 0 { a.atime = get_u32(r, m); a.mtime = get_u32(r, m); }
    if (flags & ATTR_EXTENDED) != 0 {
        let n = get_u32(r, m);
        var i: u32 = 0;
        while i < n && !r.bad {
            let t = get_string(r, m);
            let d = get_string(r, m);
            i++;
        }
    }
    a.flags = flags & (ATTR_SIZE | ATTR_UIDGID | ATTR_PERMISSIONS | ATTR_ACMODTIME);
    return a;
}

// --- Packets ------------------------------------------------------------------

// The length of the whole packet at buf's start (its length field
// included): > 0 when it is all there, 0 when more is needed, -1 for one
// that is empty or longer than SFTP_MAX_PACKET.
fn sftp_packet_len(buf: const u8[:]) -> i64 {
    if buf.len < 4 { return 0; }
    var n: i64 = 0;
    for i in 4 { n = n << 8 | buf[i]; }
    if n == 0 || n > SFTP_MAX_PACKET { return -1; }
    return if buf.len >= 4 + n { 4 + n } else { 0 };
}

// A packet of `kind`: sftp_begin, its fields, then sftp_end with what
// sftp_begin returned.
fn sftp_begin(out: u8[>..]&, kind: u8) -> i64 {
    let mark = begin_string(out);
    out.push(kind);
    return mark;
}

fn sftp_end(out: u8[>..]&, mark: i64) { end_string(out, mark); }

// A request: its type and id; its fields follow, then sftp_end.
fn sftp_req(out: u8[>..]&, kind: u8, id: u32) -> i64 {
    let mark = sftp_begin(out, kind);
    put_u32(out, id);
    return mark;
}

// A packet read: its type, its id (the version, for INIT and VERSION), and
// a cursor over the rest.
struct SftpMsg { kind: u8, id: u32, body: Rd }

// m is one whole packet (sftp_packet_len's bytes); false if it is short or
// its length field is not its size.
fn sftp_parse(m: const u8[:]) -> SftpMsg, bool {
    var r = rd(m);
    let n: i64 = get_u32(r, m);
    let kind = get_u8(r, m);
    let id = get_u32(r, m);
    let ok = !r.bad && n == m.len - 4;
    return SftpMsg { kind: kind, id: id, body: Rd { pos: r.pos, end: m.len, bad: !ok } }, ok;
}

// --- The client's requests -------------------------------------------------------

fn sftp_init(out: u8[>..]&) {
    let mark = sftp_begin(out, FXP_INIT);
    put_u32(out, SFTP_VERSION);
    sftp_end(out, mark);
}

// LSTAT, STAT, OPENDIR, REMOVE, RMDIR, REALPATH and READLINK: a path.
fn sftp_path_req(out: u8[>..]&, kind: u8, id: u32, path: const u8[:]) {
    let mark = sftp_req(out, kind, id);
    put_string(out, path);
    sftp_end(out, mark);
}

// CLOSE, READDIR and FSTAT: a handle.
fn sftp_handle_req(out: u8[>..]&, kind: u8, id: u32, handle: const u8[:]) {
    let mark = sftp_req(out, kind, id);
    put_string(out, handle);
    sftp_end(out, mark);
}

fn sftp_open(out: u8[>..]&, id: u32, path: const u8[:], pflags: u32, a: Attrs) {
    let mark = sftp_req(out, FXP_OPEN, id);
    put_string(out, path);
    put_u32(out, pflags);
    put_attrs(out, a);
    sftp_end(out, mark);
}

fn sftp_read(out: u8[>..]&, id: u32, handle: const u8[:], offset: u64, len: u32) {
    let mark = sftp_req(out, FXP_READ, id);
    put_string(out, handle);
    put_u64(out, offset);
    put_u32(out, len);
    sftp_end(out, mark);
}

fn sftp_write(out: u8[>..]&, id: u32, handle: const u8[:], offset: u64, data: const u8[:]) {
    let mark = sftp_req(out, FXP_WRITE, id);
    put_string(out, handle);
    put_u64(out, offset);
    put_string(out, data);
    sftp_end(out, mark);
}

// SETSTAT (a path) and FSETSTAT (a handle).
fn sftp_setstat(out: u8[>..]&, kind: u8, id: u32, path_or_handle: const u8[:], a: Attrs) {
    let mark = sftp_req(out, kind, id);
    put_string(out, path_or_handle);
    put_attrs(out, a);
    sftp_end(out, mark);
}

fn sftp_mkdir(out: u8[>..]&, id: u32, path: const u8[:], a: Attrs) {
    let mark = sftp_req(out, FXP_MKDIR, id);
    put_string(out, path);
    put_attrs(out, a);
    sftp_end(out, mark);
}

// RENAME, and SYMLINK in OpenSSH's order: the target, then the link.
fn sftp_two_paths(out: u8[>..]&, kind: u8, id: u32, a: const u8[:], b: const u8[:]) {
    let mark = sftp_req(out, kind, id);
    put_string(out, a);
    put_string(out, b);
    sftp_end(out, mark);
}

// An EXTENDED request: its name; its fields follow, then sftp_end.
fn sftp_extended(out: u8[>..]&, id: u32, name: const u8[:]) -> i64 {
    let mark = sftp_req(out, FXP_EXTENDED, id);
    put_string(out, name);
    return mark;
}

// --- The server's replies --------------------------------------------------------

// VERSION: then put_string pairs of extension name and data, then sftp_end.
fn sftp_version(out: u8[>..]&) -> i64 {
    let mark = sftp_begin(out, FXP_VERSION);
    put_u32(out, SFTP_VERSION);
    return mark;
}

fn sftp_status_text(code: u32) -> const u8[:] {
    if code == FX_OK { return "Success"; }
    if code == FX_EOF { return "End of file"; }
    if code == FX_NO_SUCH_FILE { return "No such file"; }
    if code == FX_PERMISSION_DENIED { return "Permission denied"; }
    if code == FX_FAILURE { return "Failure"; }
    if code == FX_BAD_MESSAGE { return "Bad message"; }
    if code == FX_NO_CONNECTION { return "No connection"; }
    if code == FX_CONNECTION_LOST { return "Connection lost"; }
    if code == FX_OP_UNSUPPORTED { return "Operation unsupported"; }
    return "Unknown error";
}

// STATUS, with OpenSSH's message for the code and no language tag.
fn sftp_status(out: u8[>..]&, id: u32, code: u32) { sftp_status_message(out, id, code, sftp_status_text(code)); }

fn sftp_status_message(out: u8[>..]&, id: u32, code: u32, message: const u8[:]) {
    let mark = sftp_req(out, FXP_STATUS, id);
    put_u32(out, code);
    put_string(out, message);
    put_string(out, "");
    sftp_end(out, mark);
}

fn sftp_handle(out: u8[>..]&, id: u32, handle: const u8[:]) {
    let mark = sftp_req(out, FXP_HANDLE, id);
    put_string(out, handle);
    sftp_end(out, mark);
}

fn sftp_data(out: u8[>..]&, id: u32, data: const u8[:]) {
    let mark = sftp_req(out, FXP_DATA, id);
    put_string(out, data);
    sftp_end(out, mark);
}

fn sftp_attrs(out: u8[>..]&, id: u32, a: Attrs) {
    let mark = sftp_req(out, FXP_ATTRS, id);
    put_attrs(out, a);
    sftp_end(out, mark);
}

// NAME: sftp_name_begin, then sftp_name_add for each entry, then
// sftp_name_end with the mark and the count.
fn sftp_name_begin(out: u8[>..]&, id: u32) -> i64 {
    let mark = sftp_req(out, FXP_NAME, id);
    put_u32(out, 0);
    return mark;
}

fn sftp_name_add(out: u8[>..]&, filename: const u8[:], longname: const u8[:], a: Attrs) {
    put_string(out, filename);
    put_string(out, longname);
    put_attrs(out, a);
}

fn sftp_name_end(out: u8[>..]&, mark: i64, count: u32) {
    // The count follows the length, the type and the id.
    for i in 4 { out[mark + 9 + i] = (count >> (24 - 8 * i)) as! u8; }
    sftp_end(out, mark);
}

// --- Reading replies -------------------------------------------------------------

// A STATUS's code and message; FX_BAD_MESSAGE if it does not parse. The
// language tag is optional (OpenSSH's older servers leave it out).
fn sftp_get_status(m: const u8[:], msg: const SftpMsg&) -> u32, Rd {
    var r = msg.body;
    let code = get_u32(r, m);
    let text = get_string(r, m);
    if r.bad || msg.kind != FXP_STATUS { return FX_BAD_MESSAGE, empty_rd(); }
    return code, text;
}

// The value of an extension a VERSION names; false if it names none.
fn sftp_extension(m: const u8[:], msg: const SftpMsg&, name: const u8[:]) -> const u8[:], bool {
    var r = msg.body;
    while r.pos < r.end {
        let n = get_string(r, m);
        let v = get_string(r, m);
        if r.bad { break; }
        if bytes(m, n) == name { return bytes(m, v), true; }
    }
    return "", false;
}

// --- ls -l ---------------------------------------------------------------------

// The ten characters of ls -l for a mode: the type, then rwx three times,
// with s, S, t and T for the set-id and sticky bits.
fn sftp_mode_string(out: u8[>..]&, perm: u32) {
    let t = perm & S_IFMT;
    out.push(if t == S_IFDIR { 'd' } else if t == S_IFLNK { 'l' } else if t == 0x2000 { 'c' }
             else if t == 0x6000 { 'b' } else if t == 0x1000 { 'p' } else if t == 0xc000 { 's' }
             else if t == S_IFREG { '-' } else { '?' });
    let rwx = "rwx";
    for k in 3 {
        let bits = (perm >> (6 - 3 * k)) & 7;
        out.push(if (bits & 4) != 0 { rwx[0] } else { '-' });
        out.push(if (bits & 2) != 0 { rwx[1] } else { '-' });
        let special = (perm >> (11 - k)) & 1;          // setuid, setgid, sticky
        let x = (bits & 1) != 0;
        let mark: u8 = if k == 2 { if x { 't' } else { 'T' } } else { if x { 's' } else { 'S' } };
        out.push(if special != 0 { mark } else if x { 'x' } else { '-' });
    }
}

// Days since 1970-01-01 as year, month (1-12) and day (Howard Hinnant's
// civil_from_days).
fn civil_from_days(days: i64) -> i64, i64, i64 {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (if mo <= 2 { 1 } else { 0 });
    return y, mo, d;
}

fn pad_left(out: u8[>..]&, s: const u8[:], width: i64) {
    for i in width - s.len { out.push(' '); }
    out.append(s);
}

fn pad_right(out: u8[>..]&, s: const u8[:], width: i64) {
    out.append(s);
    for i in width - s.len { out.push(' '); }
}

// A NAME entry's longname, as OpenSSH's sftp-server writes it (ls -l):
// mode, links, owner, group, size, the modification time (UTC; the year
// instead of the time for one more than six months from now), the name.
fn sftp_longname(out: u8[>..]&, name: const u8[:], a: Attrs, nlink: u64, owner: const u8[:], group: const u8[:], now: i64) {
    sftp_mode_string(out, a.perm);
    out.push(' ');
    var n: u8[>..] = [];
    format_uint(n, nlink, 10, 0, ' ');
    pad_left(out, n, 3);
    out.push(' ');
    pad_right(out, owner, 8);
    out.push(' ');
    pad_right(out, group, 8);
    out.push(' ');
    n.clear();
    format_uint(n, a.size, 10, 0, ' ');
    pad_left(out, n, 8);
    out.push(' ');
    let t: i64 = a.mtime;
    var days = t / 86400;
    let secs = t - days * 86400;
    let y, mo, d = civil_from_days(days);
    let months = "JanFebMarAprMayJunJulAugSepOctNovDec";
    out.append(months[3 * (mo - 1)..3 * mo]);
    out.push(' ');
    out.push(if d >= 10 { ('0' + d / 10) as! u8 } else { ' ' });
    out.push(('0' + d % 10) as! u8);
    out.push(' ');
    let half_year: i64 = 182 * 86400;
    if t > now - half_year && t < now + half_year {
        let h = secs / 3600;
        let mi = secs / 60 % 60;
        out.push(('0' + h / 10) as! u8);
        out.push(('0' + h % 10) as! u8);
        out.push(':');
        out.push(('0' + mi / 10) as! u8);
        out.push(('0' + mi % 10) as! u8);
    } else {
        n.clear();
        format_int(n, y, 10, 0, ' ');
        pad_left(out, n, 5);
    }
    out.push(' ');
    out.append(name);
}
