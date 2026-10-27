// Port forwarding's sockets for tools/ssh.goose and tools/sshd.goose: the
// listeners (the client's -L and -D, the server's for -R), and the links
// between a socket and a channel. A link's socket is read only as far as
// the channel's window allows, so nothing waits in a buffer; EOF goes each
// way, and the channel is closed once both ways have ended. -D speaks
// SOCKS5 (RFC 1928: CONNECT, no authentication) to its clients, as
// OpenSSH's does.
namespace relay;

import std;
import os;
import ssh.conn;
import .sysnet;

let FWD_LOCAL: i64 = 1;          // client, -L: connections become direct-tcpip channels to host:hostport
let FWD_DYNAMIC: i64 = 2;        // client, -D: SOCKS5, then direct-tcpip
let FWD_REMOTE: i64 = 3;         // server, for -R: connections become forwarded-tcpip channels (host: the address the client asked for)

struct Listener { kind: i64, fd: i32, bind: u8[..256], port: i64, host: u8[..256], hostport: i64 }

let LINK_FREE: i64 = 0;
let LINK_SOCKS: i64 = 1;         // reading the SOCKS greeting and request
let LINK_OPENING: i64 = 2;       // the channel asked for
let LINK_OPEN: i64 = 3;

// A socket and its channel: the socket's end of file seen, the channel's
// EOF received, a SOCKS reply owed when the channel opens, and the SOCKS
// bytes read so far (greeting done once `greeted`).
struct Link { state: i64, fd: i32, ch: i64, sock_eof: bool, chan_eof: bool, socks_reply: bool, greeted: bool,
              socks: u8[..600] }

struct Relay { listeners: Listener[..16], links: Link[..48], verbose: bool }

fn new_relay(verbose: bool) -> Relay { Relay { listeners: [], links: [], verbose: verbose } }

fn log(r: const Relay&, s: const u8[:]) { if r.verbose { sysnet::eprint(str("forward: ", s, "\n")); } }

fn no_link() -> Link { Link { state: LINK_FREE, fd: -1, ch: -1, sock_eof: false, chan_eof: false, socks_reply: false, greeted: false, socks: [] } }

// Listens for a forward: false if the address cannot be had. Port 0 takes
// any; l.port is then the one taken.
fn listen(r: Relay&, kind: i64, bind: const u8[:], port: i64, host: const u8[:], hostport: i64) -> bool {
    if r.listeners.len == r.listeners.cap { return false; }
    let fd = sysnet::net_listen(bind, port as! i32);
    if fd < 0 { return false; }
    var l = Listener { kind: kind, fd: fd, bind: [], port: port, host: [], hostport: hostport };
    l.bind.append(bind);
    l.host.append(host);
    if port == 0 { l.port = sysnet::net_local_port(fd); }
    r.listeners.push(l);
    return true;
}

// The listener on bind:port (a server's for -R), or -1.
fn listener_at(r: const Relay&, port: i64) -> i64 {
    for i in r.listeners.len { if r.listeners[i].fd >= 0 && r.listeners[i].port == port { return i; } }
    return -1;
}

fn close_listener(r: Relay&, i: i64) {
    sysnet::net_close(r.listeners[i].fd);
    r.listeners[i].fd = -1;
}

fn add_link(r: Relay&, fd: i32, ch: i64, state: i64) -> i64 {
    var slot = -1;
    for i in r.links.len { if slot < 0 && r.links[i].state == LINK_FREE { slot = i; } }
    if slot < 0 {
        if r.links.len == r.links.cap { return -1; }
        r.links.push(no_link());
        slot = r.links.len - 1;
    }
    r.links[slot] = no_link();
    r.links[slot].state = state;
    r.links[slot].fd = fd;
    r.links[slot].ch = ch;
    return slot;
}

fn free_link(r: Relay&, i: i64) {
    sysnet::net_close(r.links[i].fd);
    r.links[i] = no_link();
}

fn link_of(r: const Relay&, ch: i64) -> i64 {
    for i in r.links.len { if r.links[i].state != LINK_FREE && r.links[i].ch == ch { return i; } }
    return -1;
}

// Connects a channel the peer opened (direct-tcpip on the server,
// forwarded-tcpip on the client) to host:port: accepted with a link, or
// refused.
fn connect_channel(r: Relay&, c: ssh::Conn&, ch: i64, host: const u8[:], port: i64, out: u8[>..]&) -> bool {
    let fd = if port > 0 && port < 65536 { sysnet::net_connect(host, port as! i32) } else { -1 };
    if fd < 0 || add_link(r, fd, ch, LINK_OPEN) < 0 {
        if fd >= 0 { sysnet::net_close(fd); }
        log(r, str("cannot connect to ", host, ":", port));
        let x = ssh::channel_reject(c, ch, ssh::OPEN_CONNECT_FAILED, "connect failed", out);
        return false;
    }
    log(r, str("connected to ", host, ":", port));
    return ssh::channel_accept(c, ch, out);
}

// The descriptors to wait on: each listener's, and each link's socket that
// can be read now (SOCKS bytes, or data the channel's window takes).
fn poll_fds(r: const Relay&, c: const ssh::Conn&, fds: i32[>..]&) {
    for l in r.listeners { fds.push(l.fd); }
    for k in r.links {
        let ready = k.state == LINK_SOCKS || (k.state == LINK_OPEN && !k.sock_eof && ssh::channel_window(c, k.ch) > 0);
        fds.push(if ready { k.fd } else { -1 });
    }
}

// The channel's end: closed once neither way has more.
fn maybe_close(r: Relay&, c: ssh::Conn&, i: i64, out: u8[>..]&) {
    if r.links[i].sock_eof && r.links[i].chan_eof { ssh::channel_close(c, r.links[i].ch, out); }
}

// Acts on what poll found: fds and ready from `base` are poll_fds' (a
// descriptor closed and its slot reused since is not taken for ready).
fn service(r: Relay&, c: ssh::Conn&, fds: const i32[:], ready: const u8[:], base: i64, out: u8[>..]&) {
    let nl = ::min(r.listeners.len, fds.len - base);
    for i in nl {
        if ready[base + i] == 0 || r.listeners[i].fd < 0 || fds[base + i] != r.listeners[i].fd { continue; }
        var peer: u8[64] = [0; 64];
        var plen: i64 = 0;
        var pport: i32 = 0;
        let fd = sysnet::net_accept(r.listeners[i].fd, peer, plen, pport);
        if fd < 0 { continue; }
        let l = r.listeners[i];
        if l.kind == FWD_DYNAMIC {
            if add_link(r, fd, -1, LINK_SOCKS) < 0 { sysnet::net_close(fd); }
            continue;
        }
        let ch = if l.kind == FWD_LOCAL { ssh::open_direct_tcpip(c, l.host, l.hostport as! u32, peer[..plen], pport as! u32, out) }
                 else { ssh::open_forwarded_tcpip(c, l.host, l.port as! u32, peer[..plen], pport as! u32, out) };
        if ch < 0 || add_link(r, fd, ch, LINK_OPENING) < 0 {
            sysnet::net_close(fd);
            continue;
        }
        log(r, str("connection from ", peer[..plen], ":", pport, " on port ", l.port));
    }
    for i in r.links.len {
        if base + nl + i >= fds.len { break; }
        if ready[base + nl + i] == 0 || fds[base + nl + i] != r.links[i].fd { continue; }
        if r.links[i].state == LINK_SOCKS { socks_read(r, c, i, out); continue; }
        if r.links[i].state != LINK_OPEN { continue; }
        let n = ssh::channel_window(c, r.links[i].ch);
        if n <= 0 { continue; }
        var buf: u8[32768] = [0; 32768];
        let got = sysnet::net_read(r.links[i].fd, buf[..::min(n, 32768)]);
        if got > 0 {
            let sent = ssh::channel_send(c, r.links[i].ch, buf[..got], out);
        } else {
            r.links[i].sock_eof = true;
            if got < 0 { ssh::channel_close(c, r.links[i].ch, out); }
            else { ssh::channel_eof(c, r.links[i].ch, out); maybe_close(r, c, i, out); }
        }
    }
}

// A channel event, if the channel is a link's: true when it was.
fn on_event(r: Relay&, c: ssh::Conn&, e: const ssh::Event&, events: const u8[:], out: u8[>..]&) -> bool {
    let i = link_of(r, e.channel);
    if i < 0 { return false; }
    if e.kind == ssh::EV_CHANNEL_OPENED {
        if r.links[i].socks_reply {
            let ok: u8[10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            let w = sysnet::net_write(r.links[i].fd, ok);
        }
        r.links[i].state = LINK_OPEN;
    } else if e.kind == ssh::EV_CHANNEL_OPEN_FAILED {
        if r.links[i].socks_reply {
            let refused: u8[10] = [5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
            let w = sysnet::net_write(r.links[i].fd, refused);
        }
        log(r, str("channel refused: ", ssh::bytes(events, e.data)));
        free_link(r, i);
    } else if e.kind == ssh::EV_DATA || e.kind == ssh::EV_EXTENDED_DATA {
        if sysnet::net_write(r.links[i].fd, ssh::bytes(events, e.data)) < 0 { ssh::channel_close(c, e.channel, out); }
    } else if e.kind == ssh::EV_EOF {
        r.links[i].chan_eof = true;
        sysnet::net_shutdown_write(r.links[i].fd);
        maybe_close(r, c, i, out);
    } else if e.kind == ssh::EV_CLOSE {
        free_link(r, i);
    } else {
        return false;
    }
    return true;
}

// SOCKS5 (RFC 1928): the greeting (no authentication), then CONNECT to an
// IPv4 address, a domain name or an IPv6 address, which becomes a
// direct-tcpip channel; the reply waits for the channel.
fn socks_read(r: Relay&, c: ssh::Conn&, i: i64, out: u8[>..]&) {
    var buf: u8[600] = [0; 600];
    let room = r.links[i].socks.cap - r.links[i].socks.len;
    let n = sysnet::net_read(r.links[i].fd, buf[..room]);
    if n <= 0 { free_link(r, i); return; }
    r.links[i].socks.append(buf[..n]);
    let b = r.links[i].socks[..];
    if !r.links[i].greeted {
        if b.len < 2 || b.len < 2 + b[1] { return; }
        var none = false;
        for m in b[2..2 + b[1]] { if m == 0 { none = true; } }
        if b[0] != 5 || !none {
            let no: u8[2] = [5, 0xff];
            let w = sysnet::net_write(r.links[i].fd, no);
            free_link(r, i);
            return;
        }
        let yes: u8[2] = [5, 0];
        let w = sysnet::net_write(r.links[i].fd, yes);
        r.links[i].greeted = true;
        var rest: u8[..600] = [];
        rest.append(b[2 + b[1]..]);
        r.links[i].socks = rest;
    }
    let q = r.links[i].socks[..];
    if q.len < 5 { return; }
    let atyp = q[3];
    let need = if atyp == 1 { 10 } else if atyp == 4 { 22 } else if atyp == 3 { 7 + q[4] } else { 0 };
    if need == 0 || q[0] != 5 || q[1] != 1 {
        let bad: u8[10] = [5, if q[1] != 1 { 7 } else { 8 }, 0, 1, 0, 0, 0, 0, 0, 0];
        let w = sysnet::net_write(r.links[i].fd, bad);
        free_link(r, i);
        return;
    }
    if q.len < need { return; }
    var host: u8[>..] = [];
    if atyp == 1 {
        for j in 4 {
            if j > 0 { host.push('.'); }
            format_uint(host, q[4 + j], 10, 0, ' ');
        }
    } else if atyp == 3 {
        host.append(q[5..5 + q[4]]);
    } else {
        for j in 8 {
            if j > 0 { host.push(':'); }
            format_uint(host, (q[4 + 2 * j] as u64) << 8 | q[5 + 2 * j], 16, 0, ' ');
        }
    }
    let port: u32 = (q[need - 2] as u32) << 8 | q[need - 1];
    let ch = ssh::open_direct_tcpip(c, host, port, "127.0.0.1", 0, out);
    if ch < 0 { free_link(r, i); return; }
    log(r, str("SOCKS to ", host, ":", port));
    r.links[i].ch = ch;
    r.links[i].state = LINK_OPENING;
    r.links[i].socks_reply = true;
}
