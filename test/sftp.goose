// ssh.sftp: SFTP version 3's packets, written and read back:
// - INIT and VERSION byte for byte, extensions found by name;
// - every request a client sends parses back to its fields, SYMLINK in
//   OpenSSH's order;
// - every reply a server sends likewise: STATUS with OpenSSH's messages,
//   HANDLE, DATA, ATTRS, NAME with its count;
// - ATTRS with each field and all of them, extended pairs skipped, and a
//   truncated one refused;
// - packet framing: whole, partial, empty and too long;
// - ls -l longnames: modes with set-id and sticky bits, recent and old
//   dates.
import std;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.sftp;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let digits = "0123456789abcdef";
    for x in b { out.push(digits[x >> 4]); out.push(digits[x & 15]); }
    return out;
}

// The one packet in `out`, parsed; its kind must be `kind`.
fn one(out: const u8[:], kind: u8, what: const u8[:]) -> ssh::SftpMsg {
    let n = ssh::sftp_packet_len(out);
    check(str(what, ": one whole packet"), n == out.len);
    let m, ok = ssh::sftp_parse(out);
    check(str(what, ": parses"), ok && m.kind == kind);
    return m;
}

fn same_attrs(a: const ssh::Attrs&, b: const ssh::Attrs&) -> bool {
    a.flags == b.flags && a.size == b.size && a.uid == b.uid && a.gid == b.gid && a.perm == b.perm &&
    a.atime == b.atime && a.mtime == b.mtime
}

fn init_and_version() {
    var out: u8[>..] = [];
    ssh::sftp_init(out);
    check("INIT bytes", hex(out) == "000000050100000003");
    let m = one(out, ssh::FXP_INIT, "INIT");
    check("INIT version", m.id == 3);
    out.clear();
    let mark = ssh::sftp_version(out);
    ssh::put_string(out, "posix-rename@openssh.com");
    ssh::put_string(out, "1");
    ssh::put_string(out, "limits@openssh.com");
    ssh::put_string(out, "1");
    ssh::sftp_end(out, mark);
    let v = one(out, ssh::FXP_VERSION, "VERSION");
    check("VERSION version", v.id == 3);
    let x, ok = ssh::sftp_extension(out, v, "limits@openssh.com");
    check("an extension found", ok && x == "1");
    let y, ok2 = ssh::sftp_extension(out, v, "copy-data");
    check("an extension not there", !ok2);
}

fn attrs() {
    var all = ssh::Attrs { flags: ssh::ATTR_SIZE | ssh::ATTR_UIDGID | ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME,
                           size: 0x0123456789abcdef, uid: 501, gid: 20, perm: 0x81a4, atime: 1700000000, mtime: 1700000001 };
    let masks: u32[6] = [0, ssh::ATTR_SIZE, ssh::ATTR_UIDGID, ssh::ATTR_PERMISSIONS, ssh::ATTR_ACMODTIME, all.flags];
    for f in masks {
        var a = all;
        a.flags = f;
        if (f & ssh::ATTR_SIZE) == 0 { a.size = 0; }
        if (f & ssh::ATTR_UIDGID) == 0 { a.uid = 0; a.gid = 0; }
        if (f & ssh::ATTR_PERMISSIONS) == 0 { a.perm = 0; }
        if (f & ssh::ATTR_ACMODTIME) == 0 { a.atime = 0; a.mtime = 0; }
        var out: u8[>..] = [];
        ssh::put_attrs(out, a);
        var r = ssh::rd(out);
        let b = ssh::get_attrs(r, out);
        check(str("ATTRS round trip, flags ", f), ssh::done(r) && same_attrs(a, b));
    }
    // Every field: size, uid, gid, perm, atime, mtime in order.
    var out: u8[>..] = [];
    ssh::put_attrs(out, all);
    check("ATTRS bytes", hex(out) == "0000000f0123456789abcdef000001f500000014000081a46553f1006553f101");
    // Extended pairs are read past.
    var ext: u8[>..] = [];
    ssh::put_u32(ext, ssh::ATTR_EXTENDED | ssh::ATTR_SIZE);
    ssh::put_u64(ext, 7);
    ssh::put_u32(ext, 2);
    ssh::put_string(ext, "a@x"); ssh::put_string(ext, "1");
    ssh::put_string(ext, "b@x"); ssh::put_string(ext, "22");
    ssh::put_u32(ext, 0xdeadbeef);
    var r = ssh::rd(ext);
    let e = ssh::get_attrs(r, ext);
    check("ATTRS extended pairs skipped", !r.bad && e.flags == ssh::ATTR_SIZE && e.size == 7 && ssh::get_u32(r, ext) == 0xdeadbeef);
    // Cut anywhere, it overruns.
    var bad = 0;
    for cut in out.len {
        var r2 = ssh::rd(out[..cut]);
        let x = ssh::get_attrs(r2, out[..cut]);
        if !r2.bad { bad++; }
    }
    check("ATTRS truncated: refused at every length", bad == 0);
}

fn requests() {
    var out: u8[>..] = [];
    ssh::sftp_open(out, 7, "dir/file", ssh::FXF_WRITE | ssh::FXF_CREAT | ssh::FXF_TRUNC, ssh::perm_attrs(0x1a4));
    var m = one(out, ssh::FXP_OPEN, "OPEN");
    var r = m.body;
    let p = ssh::get_string(r, out);
    let fl = ssh::get_u32(r, out);
    let a = ssh::get_attrs(r, out);
    check("OPEN fields", m.id == 7 && ssh::bytes(out, p) == "dir/file" && fl == 0x1a && a.flags == ssh::ATTR_PERMISSIONS &&
          a.perm == 0x1a4 && ssh::done(r));

    out.clear();
    ssh::sftp_read(out, 8, "h1", 1 << 40, 32768);
    m = one(out, ssh::FXP_READ, "READ");
    r = m.body;
    let h = ssh::get_string(r, out);
    let off = ssh::get_u64(r, out);
    let len = ssh::get_u32(r, out);
    check("READ fields", m.id == 8 && ssh::bytes(out, h) == "h1" && off == 1 << 40 && len == 32768 && ssh::done(r));
    check("READ bytes", hex(out) == "000000170500000008000000026831000001000000000000008000");

    out.clear();
    ssh::sftp_write(out, 9, "h2", 5, "hello");
    m = one(out, ssh::FXP_WRITE, "WRITE");
    r = m.body;
    let h2 = ssh::get_string(r, out);
    let off2 = ssh::get_u64(r, out);
    let d = ssh::get_string(r, out);
    check("WRITE fields", m.id == 9 && ssh::bytes(out, h2) == "h2" && off2 == 5 && ssh::bytes(out, d) == "hello" && ssh::done(r));

    let path_kinds: u8[7] = [ssh::FXP_LSTAT, ssh::FXP_STAT, ssh::FXP_OPENDIR, ssh::FXP_REMOVE, ssh::FXP_RMDIR,
                             ssh::FXP_REALPATH, ssh::FXP_READLINK];
    for k in path_kinds {
        out.clear();
        ssh::sftp_path_req(out, k, 10, "/a b");
        m = one(out, k, "a path request");
        r = m.body;
        let s = ssh::get_string(r, out);
        check(str("path request ", k), m.id == 10 && ssh::bytes(out, s) == "/a b" && ssh::done(r));
    }
    let handle_kinds: u8[3] = [ssh::FXP_CLOSE, ssh::FXP_READDIR, ssh::FXP_FSTAT];
    for k in handle_kinds {
        out.clear();
        ssh::sftp_handle_req(out, k, 11, "\x00\x01");
        m = one(out, k, "a handle request");
        r = m.body;
        let s = ssh::get_string(r, out);
        check(str("handle request ", k), m.id == 11 && ssh::bytes(out, s) == "\x00\x01" && ssh::done(r));
    }

    out.clear();
    var t = ssh::no_attrs();
    t.flags = ssh::ATTR_ACMODTIME;
    t.atime = 1;
    t.mtime = 2;
    ssh::sftp_setstat(out, ssh::FXP_FSETSTAT, 12, "h", t);
    m = one(out, ssh::FXP_FSETSTAT, "FSETSTAT");
    r = m.body;
    let hs = ssh::get_string(r, out);
    let ta = ssh::get_attrs(r, out);
    check("FSETSTAT fields", ssh::bytes(out, hs) == "h" && same_attrs(ta, t) && ssh::done(r));

    out.clear();
    ssh::sftp_mkdir(out, 13, "new", ssh::perm_attrs(0x1ed));
    m = one(out, ssh::FXP_MKDIR, "MKDIR");

    // SYMLINK: the target first, then the link (OpenSSH's order).
    out.clear();
    ssh::sftp_two_paths(out, ssh::FXP_SYMLINK, 14, "target", "link");
    m = one(out, ssh::FXP_SYMLINK, "SYMLINK");
    r = m.body;
    let s1 = ssh::get_string(r, out);
    let s2 = ssh::get_string(r, out);
    check("SYMLINK order", ssh::bytes(out, s1) == "target" && ssh::bytes(out, s2) == "link" && ssh::done(r));

    out.clear();
    let mk = ssh::sftp_extended(out, 15, "limits@openssh.com");
    ssh::sftp_end(out, mk);
    m = one(out, ssh::FXP_EXTENDED, "EXTENDED");
    r = m.body;
    let en = ssh::get_string(r, out);
    check("EXTENDED name", m.id == 15 && ssh::bytes(out, en) == "limits@openssh.com" && ssh::done(r));
}

fn replies() {
    var out: u8[>..] = [];
    let codes: u32[9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let texts: const u8[:][9] = ["Success", "End of file", "No such file", "Permission denied", "Failure", "Bad message",
                                 "No connection", "Connection lost", "Operation unsupported"];
    for i in 9 {
        out.clear();
        ssh::sftp_status(out, 20, codes[i]);
        let m = one(out, ssh::FXP_STATUS, "STATUS");
        let c, t = ssh::sftp_get_status(out, m);
        check(str("STATUS ", codes[i]), m.id == 20 && c == codes[i] && ssh::bytes(out, t) == texts[i]);
    }
    out.clear();
    ssh::sftp_status_message(out, 26, ssh::FX_NO_SUCH_FILE, "no such user");
    let mu = one(out, ssh::FXP_STATUS, "STATUS with a message");
    let cu, tu = ssh::sftp_get_status(out, mu);
    check("STATUS with a message", cu == ssh::FX_NO_SUCH_FILE && ssh::bytes(out, tu) == "no such user");
    // A STATUS without its language tag still reads.
    out.clear();
    let mk = ssh::sftp_req(out, ssh::FXP_STATUS, 21);
    ssh::put_u32(out, ssh::FX_EOF);
    ssh::put_string(out, "eof");
    ssh::sftp_end(out, mk);
    let ms = one(out, ssh::FXP_STATUS, "STATUS, no language tag");
    let c2, t2 = ssh::sftp_get_status(out, ms);
    check("STATUS, no language tag", c2 == ssh::FX_EOF && ssh::bytes(out, t2) == "eof");

    out.clear();
    ssh::sftp_handle(out, 22, "H");
    var m = one(out, ssh::FXP_HANDLE, "HANDLE");
    out.clear();
    ssh::sftp_data(out, 23, "xyz");
    m = one(out, ssh::FXP_DATA, "DATA");
    var r = m.body;
    let d = ssh::get_string(r, out);
    check("DATA", ssh::bytes(out, d) == "xyz" && ssh::done(r));
    out.clear();
    ssh::sftp_attrs(out, 24, ssh::perm_attrs(0x41ed));
    m = one(out, ssh::FXP_ATTRS, "ATTRS");
    r = m.body;
    let a = ssh::get_attrs(r, out);
    check("ATTRS reply", ssh::is_dir_attrs(a) && !ssh::is_reg_attrs(a) && ssh::done(r));

    out.clear();
    let nm = ssh::sftp_name_begin(out, 25);
    ssh::sftp_name_add(out, "a", "la", ssh::perm_attrs(0x8180));
    ssh::sftp_name_add(out, "b", "lb", ssh::perm_attrs(0xa1ff));
    ssh::sftp_name_end(out, nm, 2);
    m = one(out, ssh::FXP_NAME, "NAME");
    r = m.body;
    let count = ssh::get_u32(r, out);
    let f1 = ssh::get_string(r, out);
    let l1 = ssh::get_string(r, out);
    let a1 = ssh::get_attrs(r, out);
    let f2 = ssh::get_string(r, out);
    let l2 = ssh::get_string(r, out);
    let a2 = ssh::get_attrs(r, out);
    check("NAME entries", m.id == 25 && count == 2 && ssh::bytes(out, f1) == "a" && ssh::bytes(out, l1) == "la" &&
          ssh::is_reg_attrs(a1) && ssh::bytes(out, f2) == "b" && ssh::bytes(out, l2) == "lb" && ssh::is_link_attrs(a2) &&
          ssh::done(r));
    // A reply that is not a STATUS is no status.
    let c3, t3 = ssh::sftp_get_status(out, m);
    check("NAME is no STATUS", c3 == ssh::FX_BAD_MESSAGE);
}

fn framing() {
    var out: u8[>..] = [];
    ssh::sftp_write(out, 1, "h", 0, "data");
    let whole = out.len;
    var partial_ok = true;
    for n in whole { if ssh::sftp_packet_len(out[..n]) != 0 { partial_ok = false; } }
    check("framing: a part of a packet needs more", partial_ok);
    ssh::sftp_init(out);
    check("framing: two packets, the first", ssh::sftp_packet_len(out) == whole);
    check("framing: the second", ssh::sftp_packet_len(out[whole..]) == out.len - whole);
    check("framing: empty refused", ssh::sftp_packet_len("\x00\x00\x00\x00") == -1);
    check("framing: 256 KiB taken", ssh::sftp_packet_len("\x00\x04\x00\x00") == 0);
    check("framing: one byte over refused", ssh::sftp_packet_len("\x00\x04\x00\x01") == -1);
    check("framing: 2^32-1 refused", ssh::sftp_packet_len("\xff\xff\xff\xff") == -1);
    // A packet whose length field is not its size, or short of an id.
    let m, ok = ssh::sftp_parse("\x00\x00\x00\x09\x65\x00\x00");
    check("parse: shorter than its length", !ok);
    let m2, ok2 = ssh::sftp_parse("\x00\x00\x00\x02\x65\x00");
    check("parse: no id", !ok2);
}

fn longnames() {
    var a = ssh::no_attrs();
    a.flags = ssh::ATTR_SIZE | ssh::ATTR_PERMISSIONS | ssh::ATTR_ACMODTIME;
    a.size = 1234;
    a.perm = 0x81a4;
    a.mtime = 1700000000;                 // 2023-11-14 22:13:20 UTC
    var out: u8[>..] = [];
    ssh::sftp_longname(out, "f.txt", a, 1, "alice", "staff", 1700000000 + 86400);
    check("longname, recent", out == "-rw-r--r--   1 alice    staff        1234 Nov 14 22:13 f.txt");
    out.clear();
    ssh::sftp_longname(out, "old", a, 12, "1000", "1000", 1800000000);
    check("longname, a year old", out == "-rw-r--r--  12 1000     1000         1234 Nov 14  2023 old");
    let modes: u32[6] = [0x89ed, 0x89a4, 0x43ff, 0x43fe, 0x85e8, 0xa1ff];
    let want: const u8[:][6] = ["-rwsr-xr-x", "-rwSr--r--", "drwxrwxrwt", "drwxrwxrwT", "-rwxr-s---", "lrwxrwxrwx"];
    for i in 6 {
        var s: u8[>..] = [];
        ssh::sftp_mode_string(s, modes[i]);
        check(str("mode string ", want[i]), s == want[i]);
    }
    // Days to dates: the epoch, a leap day, the end of 2099.
    let y0, m0, d0 = ssh::civil_from_days(0);
    let y1, m1, d1 = ssh::civil_from_days(11016);
    let y2, m2, d2 = ssh::civil_from_days(47481);
    check("civil dates", y0 == 1970 && m0 == 1 && d0 == 1 && y1 == 2000 && m1 == 2 && d1 == 29 && y2 == 2099 && m2 == 12 && d2 == 31);
}

fn main() {
    init_and_version();
    attrs();
    requests();
    replies();
    framing();
    longnames();
    print("sftp: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
