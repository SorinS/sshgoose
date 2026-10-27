// Port forwarding (RFC 4254 §7) between this package's client and server,
// in memory, the test playing both applications:
// - direct-tcpip (-L, -D): the server sees the target and the originator,
//   accepts, and data crosses both ways through EOF and close; a target it
//   refuses gets the reason;
// - tcpip-forward (-R) on port 0: the server answers with the port it took;
//   then forwarded-tcpip channels from it, which the client accepts, data
//   both ways; cancel-tcpip-forward; an unknown request refused;
// - 40 forwarding channels open at once, and channel_window.
import std;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import ssh.conn;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

// What each side's application saw.
struct Apps {
    targets: u8[..4096],            // "host:port from orig:oport" lines the server was asked for
    server_got: u8[..65536], client_got: u8[..65536],
    replies: u8[..256],             // the client's global replies: "1:port" or "0"
    forwarded_opens: i64, opened: i64, open_failed: u32, closes: i64,
}

fn apps() -> Apps {
    Apps { targets: [], server_got: [], client_got: [], replies: [], forwarded_opens: 0, opened: 0, open_failed: 0, closes: 0 }
}

// The server: direct-tcpip to "refused.example" is refused, the rest taken;
// data comes back as "echo:" and the data; tcpip-forward on port 0 takes
// 8080; cancel-tcpip-forward succeeds; anything else fails.
fn server_app(s: ssh::Conn&, ev: const u8[:], out: u8[>..]&, a: Apps&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(ev, pos);
        if !ok { break; }
        var r = e.data;
        if e.kind == ssh::EV_CHANNEL_OPEN {
            let kind = ssh::get_string(r, ev);
            let host = ssh::get_string(r, ev);
            let port = ssh::get_u32(r, ev);
            let oh = ssh::get_string(r, ev);
            let op = ssh::get_u32(r, ev);
            a.targets.append(str(ssh::bytes(ev, host), ":", port, " from ", ssh::bytes(ev, oh), ":", op, "\n"));
            if ssh::bytes(ev, kind) == "direct-tcpip" && ssh::bytes(ev, host) != "refused.example" {
                let x = ssh::channel_accept(s, e.channel, out);
            } else {
                let x = ssh::channel_reject(s, e.channel, ssh::OPEN_CONNECT_FAILED, "connection refused", out);
            }
        } else if e.kind == ssh::EV_DATA {
            a.server_got.append(ssh::bytes(ev, e.data));
            let n = ssh::channel_send(s, e.channel, str("echo:", ssh::bytes(ev, e.data)), out);
        } else if e.kind == ssh::EV_EOF {
            ssh::channel_eof(s, e.channel, out);
            ssh::channel_close(s, e.channel, out);
        } else if e.kind == ssh::EV_GLOBAL_REQUEST {
            let name = ssh::get_string(r, ev);
            let nm = ssh::bytes(ev, name);
            if nm == "tcpip-forward" {
                let addr = ssh::get_string(r, ev);
                let port = ssh::get_u32(r, ev);
                var f: u8[>..] = [];
                if port == 0 { ssh::put_u32(f, 8080); }
                let x = ssh::global_reply(s, true, f, out);
            } else if nm == "cancel-tcpip-forward" {
                let x = ssh::global_reply(s, true, "", out);
            } else if e.value == 1 {
                let x = ssh::global_reply(s, false, "", out);
            }
        }
    }
}

// The client: forwarded-tcpip channels are accepted; data is kept.
fn client_app(c: ssh::Conn&, ev: const u8[:], out: u8[>..]&, a: Apps&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(ev, pos);
        if !ok { break; }
        var r = e.data;
        if e.kind == ssh::EV_CHANNEL_OPEN {
            let kind = ssh::get_string(r, ev);
            if ssh::bytes(ev, kind) == "forwarded-tcpip" {
                a.forwarded_opens++;
                let x = ssh::channel_accept(c, e.channel, out);
            }
        } else if e.kind == ssh::EV_CHANNEL_OPENED {
            a.opened++;
        } else if e.kind == ssh::EV_CHANNEL_OPEN_FAILED {
            a.open_failed = e.value;
        } else if e.kind == ssh::EV_DATA {
            a.client_got.append(ssh::bytes(ev, e.data));
        } else if e.kind == ssh::EV_CLOSE {
            a.closes++;
        } else if e.kind == ssh::EV_GLOBAL_REPLY {
            if e.value == 1 && e.data.end - e.data.pos == 4 {
                var rr = e.data;
                a.replies.append(str("1:", ssh::get_u32(rr, ev), " "));
            } else {
                a.replies.append(str(e.value, " "));
            }
        }
    }
}

fn pump(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&, ts: u8[>..]&,
        tc: u8[>..]&, a: Apps&) {
    for round in 100 {
        if ts.len == 0 && tc.len == 0 { break; }
        var sev: u8[>..] = [];
        var so: u8[>..] = [];
        let rs = ssh::server_feed(s, sc, ts, so, sev);
        ts.clear();
        server_app(s, sev, so, a);
        tc.append(so);
        var cev: u8[>..] = [];
        var co: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, tc, co, cev);
        tc.clear();
        client_app(c, cev, co, a);
        ts.append(co);
    }
}

fn main() {
    let hk, e1 = ssh::parse_private_key(embed_file("vectors/key_ed25519"));
    let uk, e2 = ssh::parse_private_key(embed_file("vectors/key_ecdsa256"));
    var sc = ssh::server_config();
    let a1 = ssh::add_host_key(sc, hk);
    sc.authorized_keys.append(ssh::marshal_authorized_key(uk.public));
    var cc = ssh::client_config("alice", "example.com");
    cc.host_key_check = ssh::HOST_KEY_FIXED;
    cc.fixed_host_key.append(hk.public.blob);
    let a2 = ssh::add_key(cc, uk);
    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var ts: u8[>..] = [];
    var tc: u8[>..] = [];
    var a = apps();
    ssh::client_start(c, cc, ts);
    ssh::server_start(s, sc, tc);
    pump(c, cc, s, sc, ts, tc, a);
    check("connected", ssh::connected(c) && ssh::connected(s));

    // direct-tcpip: open, data both ways, EOF, close.
    let ch = ssh::open_direct_tcpip(c, "db.internal", 5432, "127.0.0.1", 50000, ts);
    pump(c, cc, s, sc, ts, tc, a);
    check("direct-tcpip target", a.targets == "db.internal:5432 from 127.0.0.1:50000\n" && a.opened == 1);
    check("window", ssh::channel_window(c, ch) == 32768);
    let n = ssh::channel_send(c, ch, "SELECT 1;", ts);
    pump(c, cc, s, sc, ts, tc, a);
    check("direct-tcpip data", a.server_got == "SELECT 1;" && a.client_got == "echo:SELECT 1;");
    ssh::channel_eof(c, ch, ts);
    pump(c, cc, s, sc, ts, tc, a);
    check("direct-tcpip closed", a.closes == 1 && ssh::channel_window(c, ch) == 0);
    let refused = ssh::open_direct_tcpip(c, "refused.example", 80, "127.0.0.1", 50001, ts);
    pump(c, cc, s, sc, ts, tc, a);
    check("direct-tcpip refused", a.open_failed == ssh::OPEN_CONNECT_FAILED);

    // tcpip-forward on port 0, then forwarded-tcpip channels from the server.
    check("tcpip-forward", ssh::tcpip_forward(c, "localhost", 0, ts));
    pump(c, cc, s, sc, ts, tc, a);
    check("tcpip-forward reply", a.replies == "1:8080 ");
    let fch = ssh::open_forwarded_tcpip(s, "localhost", 8080, "10.0.0.5", 41000, tc);
    pump(c, cc, s, sc, ts, tc, a);
    check("forwarded-tcpip opened", a.forwarded_opens == 1 && fch >= 0 && ssh::channel_window(s, fch) == 32768);
    a.client_got.clear();
    let n2 = ssh::channel_send(s, fch, "GET / HTTP/1.0\r\n\r\n", tc);
    pump(c, cc, s, sc, ts, tc, a);
    check("forwarded-tcpip data", a.client_got == "GET / HTTP/1.0\r\n\r\n");
    check("cancel", ssh::cancel_tcpip_forward(c, "localhost", 8080, ts));
    check("unknown request", ssh::global_request(c, "no-such@example.com", true, "", ts));
    pump(c, cc, s, sc, ts, tc, a);
    check("replies in order", a.replies == "1:8080 1 0 ");

    // 40 at once.
    a.opened = 0;
    var chans: i64[>..] = [];
    for i in 40 { chans.push(ssh::open_direct_tcpip(c, "many.example", (1000 + i) as! u32, "127.0.0.1", 1, ts)); }
    pump(c, cc, s, sc, ts, tc, a);
    var distinct = true;
    for i in 40 { if chans[i] < 0 { distinct = false; } }
    check("40 channels", distinct && a.opened == 40);
    a.server_got.clear();
    for i in 40 { let m = ssh::channel_send(c, chans[i], "x", ts); }
    pump(c, cc, s, sc, ts, tc, a);
    check("40 channels' data", a.server_got.len == 40);
    print("forward: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
