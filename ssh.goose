// ssh: the Secure Shell protocol (RFC 4251-4254) for the Goose language,
// on bignum's primitives, as Go's golang.org/x/crypto/ssh has it. This
// module holds the message numbers and the wire encoding (RFC 4251 §5):
// integers, strings, mpints and name-lists, written into builders and read
// back with a cursor. ssh.keys has the keys and signatures, ssh.cipher the
// packet protection, ssh.kex the key exchanges, and ssh.conn the
// connections. Nothing here does I/O.

namespace ssh;

import std;
import bignum from "../bigmongoose.git";
import asn1 from "../asn1goose.git";
import x509 from "../x509goose.git";

// Message numbers (RFC 4250 §4.1).
let MSG_DISCONNECT: u8 = 1;
let MSG_IGNORE: u8 = 2;
let MSG_UNIMPLEMENTED: u8 = 3;
let MSG_DEBUG: u8 = 4;
let MSG_SERVICE_REQUEST: u8 = 5;
let MSG_SERVICE_ACCEPT: u8 = 6;
let MSG_EXT_INFO: u8 = 7;
let MSG_KEXINIT: u8 = 20;
let MSG_NEWKEYS: u8 = 21;
let MSG_KEX_ECDH_INIT: u8 = 30;        // also KEXDH_INIT and the hybrid's init
let MSG_KEX_ECDH_REPLY: u8 = 31;
let MSG_KEX_DH_GEX_REQUEST: u8 = 34;
let MSG_KEX_DH_GEX_GROUP: u8 = 31;
let MSG_KEX_DH_GEX_INIT: u8 = 32;
let MSG_KEX_DH_GEX_REPLY: u8 = 33;
let MSG_USERAUTH_REQUEST: u8 = 50;
let MSG_USERAUTH_FAILURE: u8 = 51;
let MSG_USERAUTH_SUCCESS: u8 = 52;
let MSG_USERAUTH_BANNER: u8 = 53;
let MSG_USERAUTH_PK_OK: u8 = 60;       // also PASSWD_CHANGEREQ and INFO_REQUEST
let MSG_USERAUTH_INFO_REQUEST: u8 = 60;
let MSG_USERAUTH_INFO_RESPONSE: u8 = 61;
let MSG_GLOBAL_REQUEST: u8 = 80;
let MSG_REQUEST_SUCCESS: u8 = 81;
let MSG_REQUEST_FAILURE: u8 = 82;
let MSG_CHANNEL_OPEN: u8 = 90;
let MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
let MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
let MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
let MSG_CHANNEL_DATA: u8 = 94;
let MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
let MSG_CHANNEL_EOF: u8 = 96;
let MSG_CHANNEL_CLOSE: u8 = 97;
let MSG_CHANNEL_REQUEST: u8 = 98;
let MSG_CHANNEL_SUCCESS: u8 = 99;
let MSG_CHANNEL_FAILURE: u8 = 100;

// Disconnect reasons (RFC 4250 §4.2.2).
let DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
let DISCONNECT_PROTOCOL_ERROR: u32 = 2;
let DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;
let DISCONNECT_MAC_ERROR: u32 = 5;
let DISCONNECT_SERVICE_NOT_AVAILABLE: u32 = 7;
let DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
let DISCONNECT_HOST_KEY_NOT_VERIFIABLE: u32 = 9;
let DISCONNECT_CONNECTION_LOST: u32 = 10;
let DISCONNECT_BY_APPLICATION: u32 = 11;
let DISCONNECT_TOO_MANY_CONNECTIONS: u32 = 12;
let DISCONNECT_AUTH_CANCELLED_BY_USER: u32 = 13;
let DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;

// --- Writing ------------------------------------------------------------------

fn put_u8(out: u8[>..]&, v: u8) { out.push(v); }

fn put_bool(out: u8[>..]&, v: bool) { out.push(if v { 1 } else { 0 }); }

fn put_u32(out: u8[>..]&, v: u32) {
    for i in 4 { out.push((v >> (24 - 8 * i)) as! u8); }
}

fn put_u64(out: u8[>..]&, v: u64) {
    for i in 8 { out.push((v >> (56 - 8 * i)) as! u8); }
}

// A string: a 32-bit length, then the bytes.
fn put_string(out: u8[>..]&, s: const u8[:]) {
    put_u32(out, s.len as! u32);
    out.append(s);
}

// An mpint of an unsigned big-endian magnitude: leading zeros dropped, and
// a zero byte added when the top bit is set, so it does not read negative;
// zero is the empty string.
fn put_mpint(out: u8[>..]&, mag: const u8[:]) {
    var i = 0;
    while i < mag.len && mag[i] == 0 { i++; }
    let body = mag[i..];
    let lead = body.len > 0 && body[0] >= 0x80;
    put_u32(out, (body.len + (if lead { 1 } else { 0 })) as! u32);
    if lead { out.push(0); }
    out.append(body);
}

// A string whose contents are written after it: begin_string, append, then
// end_string with what it returned.
fn begin_string(out: u8[>..]&) -> i64 {
    let mark = out.len;
    put_u32(out, 0);
    return mark;
}

fn end_string(out: u8[>..]&, mark: i64) {
    let n = out.len - mark - 4;
    for i in 4 { out[mark + i] = (n >> (24 - 8 * i)) as! u8; }
}

// --- Reading ------------------------------------------------------------------

// A cursor over [pos, end) of a message; `bad` sticks once a read overruns.
struct Rd { pos: i64, end: i64, bad: bool }

fn rd(m: const u8[:]) -> Rd { Rd { pos: 0, end: m.len, bad: false } }

fn rd_at(pos: i64, end: i64) -> Rd { Rd { pos: pos, end: end, bad: false } }

fn empty_rd() -> Rd { Rd { pos: 0, end: 0, bad: false } }

fn get_u8(r: Rd&, m: const u8[:]) -> u8 {
    if r.bad || r.pos + 1 > r.end { r.bad = true; return 0; }
    r.pos++;
    return m[r.pos - 1];
}

fn get_bool(r: Rd&, m: const u8[:]) -> bool { get_u8(r, m) != 0 }

fn get_u32(r: Rd&, m: const u8[:]) -> u32 {
    if r.bad || r.pos + 4 > r.end { r.bad = true; return 0; }
    var v: u32 = 0;
    for i in 4 { v = v << 8 | m[r.pos + i]; }
    r.pos += 4;
    return v;
}

fn get_u64(r: Rd&, m: const u8[:]) -> u64 {
    let hi: u64 = get_u32(r, m);
    let lo: u64 = get_u32(r, m);
    return hi << 32 | lo;
}

// A string, as a cursor over its bytes.
fn get_string(r: Rd&, m: const u8[:]) -> Rd {
    let n: i64 = get_u32(r, m);
    if r.bad || n > r.end - r.pos { r.bad = true; return Rd { pos: r.end, end: r.end, bad: true }; }
    let s = Rd { pos: r.pos, end: r.pos + n, bad: false };
    r.pos += n;
    return s;
}

// The rest of the message.
fn get_rest(r: Rd&) -> Rd {
    let s = Rd { pos: r.pos, end: r.end, bad: r.bad };
    r.pos = r.end;
    return s;
}

// An mpint that must not be negative, as its magnitude without leading
// zeros; false for a negative or non-minimal one.
fn get_mpint(r: Rd&, m: const u8[:]) -> Rd, bool {
    let s = get_string(r, m);
    if s.bad { return s, false; }
    if s.end == s.pos { return s, true; }
    if m[s.pos] >= 0x80 { return s, false; }
    if m[s.pos] == 0 {
        if s.end - s.pos == 1 || m[s.pos + 1] < 0x80 { return s, false; }
        return Rd { pos: s.pos + 1, end: s.end, bad: false }, true;
    }
    return s, true;
}

fn done(r: const Rd&) -> bool { !r.bad && r.pos == r.end }

fn bytes(m: const u8[:], r: Rd) -> const u8[:] { m[r.pos..r.end] }

// --- Name-lists -----------------------------------------------------------------

// Whether a comma-separated name-list has a name.
fn has_name(list: const u8[:], name: const u8[:]) -> bool {
    var i = 0;
    while i <= list.len {
        var j = i;
        while j < list.len && list[j] != ',' { j++; }
        if list[i..j] == name { return true; }
        i = j + 1;
    }
    return false;
}

// The first name of the client's list that is also in the server's
// (RFC 4253 §7.1); empty for none.
fn negotiate(client: const u8[:], server: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < client.len {
        var j = i;
        while j < client.len && client[j] != ',' { j++; }
        if j > i && has_name(server, client[i..j]) {
            out.append(client[i..j]);
            return out;
        }
        i = j + 1;
    }
    return out;
}

// The names of a list that are also in another, in the first list's order:
// a configured list cut down to what this package implements, as Go's
// SetDefaults does, so that it never offers a name it can't use.
fn supported_names(list: const u8[:], supported: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < list.len {
        var j = i;
        while j < list.len && list[j] != ',' { j++; }
        if j > i && has_name(supported, list[i..j]) { add_name(out, list[i..j]); }
        i = j + 1;
    }
    return out;
}

// The first name of a list.
fn first_name(list: const u8[:]) -> u8[>..] {
    var j = 0;
    while j < list.len && list[j] != ',' { j++; }
    var out: u8[>..] = [];
    out.append(list[..j]);
    return out;
}

// Appends a name to a comma-separated list.
fn add_name(list: u8[>..]&, name: const u8[:]) {
    if list.len > 0 { list.push(','); }
    list.append(name);
}
