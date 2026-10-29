// ssh.conn between this package's client and server, in memory:
// - every key exchange, every cipher (and MAC), every host key type;
// - logging in with each key type (RSA with rsa-sha2-512 from
//   server-sig-algs), a password, keyboard-interactive, a bcrypt-hashed
//   password; a key or password the server does not take, a wrong user,
//   too many tries;
// - the host key against known_hosts: plain, hashed, another port,
//   unknown, changed, revoked; a fixed key;
// - a session: exec with output, stderr and the exit status, env and pty
//   requests, close; 3 MB each way through the windows; a rekey in the
//   middle of it, both sides' accounts, and data after it; strict KEX on.
import std;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import ssh.cipher;
import ssh.kex;
import ssh.conn;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 25 { print("FAIL ", what); } }
}

fn key(text: const u8[:]) -> ssh::PrivateKey {
    let k, e = ssh::parse_private_key(text);
    assert(e == ssh::KEY_OK);
    return k;
}

fn ed25519_key() -> ssh::PrivateKey { key(embed_file("vectors/key_ed25519")) }
fn ecdsa_key() -> ssh::PrivateKey { key(embed_file("vectors/key_ecdsa256")) }
fn ecdsa384_key() -> ssh::PrivateKey { key(embed_file("vectors/key_ecdsa384")) }
fn rsa_key() -> ssh::PrivateKey { key(embed_file("vectors/key_rsa2048")) }

// What the server application did and what the client saw.
struct Seen {
    server_auth: bool, client_auth: bool, opened: bool, out: u8[..4000000], err: u8[..4096], exit: i64, closed: bool,
    replies: i64, got_by_server: i64, banner: u8[..256], host_key: bool,
}

fn seen() -> Seen {
    Seen { server_auth: false, client_auth: false, opened: false, out: [], err: [], exit: -1, closed: false, replies: 0,
           got_by_server: 0, banner: [], host_key: false }
}

// The server's application: sessions are accepted; exec answers with the
// command, a line on stderr and exit status 3; env and pty-req are taken;
// data is counted, and echoed in kind after EOF.
fn server_app(s: ssh::Conn&, events: const u8[:], out: u8[>..]&, w: Seen&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok { break; }
        if e.kind == ssh::EV_AUTHENTICATED { w.server_auth = true; }
        if e.kind == ssh::EV_CHANNEL_OPEN {
            var r = e.data;
            let kind = ssh::get_string(r, events);
            if ssh::bytes(events, kind) == "session" { let a = ssh::channel_accept(s, e.channel, out); }
            else { let a = ssh::channel_reject(s, e.channel, ssh::OPEN_UNKNOWN_CHANNEL_TYPE, "no", out); }
        }
        if e.kind == ssh::EV_REQUEST {
            var r = e.data;
            let kind = ssh::get_string(r, events);
            let k = ssh::bytes(events, kind);
            if k == "exec" {
                let cmd = ssh::get_string(r, events);
                let a = ssh::channel_reply(s, e.channel, true, out);
                if ssh::bytes(events, cmd) == "flood" {
                    var big: u8[>..] = [];
                    for i in 3000000 { big.push((i % 251) as! u8); }
                    var sent = 0;
                    // As much as the window takes now; the rest is sent on EV_WINDOW.
                    sent = ssh::channel_send(s, e.channel, big, out);
                    w.got_by_server = sent;
                } else {
                    let n = ssh::channel_send(s, e.channel, str("ran: ", ssh::bytes(events, cmd)), out);
                    let n2 = ssh::channel_send_stderr(s, e.channel, "a line on stderr\n", out);
                    let x = ssh::exit_status(s, e.channel, 3, out);
                    ssh::channel_eof(s, e.channel, out);
                    ssh::channel_close(s, e.channel, out);
                }
            } else if k == "env" || k == "pty-req" {
                let a = ssh::channel_reply(s, e.channel, true, out);
            } else if e.value == 1 {
                let a = ssh::channel_reply(s, e.channel, false, out);
            }
        }
        if e.kind == ssh::EV_DATA { w.got_by_server += e.data.end - e.data.pos; }
    }
}

fn client_events(events: const u8[:], w: Seen&) {
    var pos = 0;
    loop {
        let e, ok = ssh::next_event(events, pos);
        if !ok { break; }
        if e.kind == ssh::EV_AUTHENTICATED { w.client_auth = true; }
        if e.kind == ssh::EV_HOST_KEY { w.host_key = true; }
        if e.kind == ssh::EV_BANNER { w.banner.append(ssh::bytes(events, e.data)); }
        if e.kind == ssh::EV_CHANNEL_OPENED { w.opened = true; }
        if e.kind == ssh::EV_DATA && w.out.len + e.data.end - e.data.pos <= w.out.cap { w.out.append(ssh::bytes(events, e.data)); }
        if e.kind == ssh::EV_EXTENDED_DATA { w.err.append(ssh::bytes(events, e.data)); }
        if e.kind == ssh::EV_EXIT_STATUS { w.exit = e.value; }
        if e.kind == ssh::EV_CLOSE { w.closed = true; }
        if e.kind == ssh::EV_REQUEST_REPLY && e.value == 1 { w.replies++; }
    }
}

// Moves bytes both ways until neither side has more to say.
fn pump(c: ssh::Conn&, cc: const ssh::ClientConfig&, s: ssh::Conn&, sc: const ssh::ServerConfig&, to_server: u8[>..]&,
        to_client: u8[>..]&, w: Seen&) {
    for round in 200 {
        if to_server.len == 0 && to_client.len == 0 { break; }
        var sev: u8[>..] = [];
        var s_out: u8[>..] = [];
        let rs = ssh::server_feed(s, sc, to_server, s_out, sev);
        to_server.clear();
        server_app(s, sev, s_out, w);
        to_client.append(s_out);
        var cev: u8[>..] = [];
        var c_out: u8[>..] = [];
        let rc = ssh::client_feed(c, cc, to_client, c_out, cev);
        to_client.clear();
        client_events(cev, w);
        to_server.append(c_out);
    }
}

fn server_cfg() -> ssh::ServerConfig {
    var sc = ssh::server_config();
    let k = ed25519_key();
    let a = ssh::add_host_key(sc, k);
    return sc;
}

// A client trusting the server's ed25519 key for "example.com".
fn client_cfg() -> ssh::ClientConfig {
    var cc = ssh::client_config("alice", "example.com");
    let hk = ed25519_key();
    cc.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(hk.public)));
    return cc;
}

struct Result { ok: bool, client_reason: u32, server_reason: u32, msg: u8[..256], w: Seen }

// A handshake and login; then, if `session`, exec of "hello".
fn connect(cc: const ssh::ClientConfig&, sc: const ssh::ServerConfig&, session: bool) -> Result {
    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var w = seen();
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    var ok = ssh::connected(c) && ssh::connected(s) && w.client_auth && w.server_auth;
    if ok && session {
        let ch = ssh::open_session(c, to_server);
        pump(c, cc, s, sc, to_server, to_client, w);
        let e1 = ssh::setenv(c, ch, "LANG", "C", to_server);
        let e2 = ssh::exec(c, ch, "hello", to_server);
        pump(c, cc, s, sc, to_server, to_client, w);
        ok = w.opened && w.out == "ran: hello" && w.err == "a line on stderr\n" && w.exit == 3 && w.closed && w.replies == 2;
    }
    var res = Result { ok: ok, client_reason: c.reason, server_reason: s.reason, msg: [], w: w };
    res.msg.append(if c.message.len > 0 { c.message[..] } else { s.message[..] });
    return res;
}

fn algorithms() {
    let kexes: const u8[:][9] = ["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org",
                                 "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                                 "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
                                 "diffie-hellman-group14-sha1"];
    for k in kexes {
        var cc = client_cfg();
        let ed = ed25519_key();
        let a = ssh::add_key(cc, ed);
        var sc = server_cfg();
        sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
        cc.kex.clear();
        cc.kex.append(k);
        sc.kex.append(",diffie-hellman-group16-sha512");
        let r = connect(cc, sc, true);
        check(str("kex ", k), r.ok);
        if !r.ok { print("   ", r.msg); }
    }
    let ciphers: const u8[:][6] = ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
                                   "aes128-ctr", "aes192-ctr", "aes256-ctr"];
    let macs: const u8[:][5] = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256",
                                "hmac-sha2-512", "hmac-sha1"];
    for ci in ciphers {
        for m in macs {
            if !ci.ends_with("-ctr") && m != macs[0] { continue; }
            var cc = client_cfg();
            let ed = ed25519_key();
            let a = ssh::add_key(cc, ed);
            var sc = server_cfg();
            sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
            cc.ciphers.clear();
            cc.ciphers.append(ci);
            cc.macs.clear();
            cc.macs.append(m);
            let r = connect(cc, sc, true);
            check(str("cipher ", ci, " ", m), r.ok);
        }
    }
    // Host key types: the server has one of each; the client asks for one.
    let hosts: const u8[:][7] = ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "rsa-sha2-512",
                                 "rsa-sha2-256", "ssh-rsa", "ssh-ed25519"];
    for h in hosts {
        var sc = ssh::server_config();
        let k1 = ed25519_key();
        let k2 = ecdsa_key();
        let k3 = ecdsa384_key();
        let k4 = rsa_key();
        let a1 = ssh::add_host_key(sc, k1);
        let a2 = ssh::add_host_key(sc, k2);
        let a3 = ssh::add_host_key(sc, k3);
        let a4 = ssh::add_host_key(sc, k4);
        var cc = ssh::client_config("alice", "example.com");
        cc.host_key_check = ssh::HOST_KEY_INSECURE;
        cc.host_key_algs.clear();
        cc.host_key_algs.append(h);
        cc.password.append("pw");
        cc.has_password = true;
        sc.passwords.append("alice:pw\n");
        let r = connect(cc, sc, false);
        check(str("host key ", h), r.ok);
    }
    // Names this package lacks, first on both sides, are not offered: the
    // next one is used. With only those, the MAC is refused (it used to
    // be chosen, and failed an assert).
    for only in 2 {
        var cc = client_cfg();
        let ed = ed25519_key();
        let a = ssh::add_key(cc, ed);
        var sc = server_cfg();
        sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
        cc.kex.clear(); cc.kex.append("diffie-hellman-group-exchange-sha256,curve25519-sha256");
        cc.ciphers.clear(); cc.ciphers.append("aes128-cbc,aes128-ctr");
        cc.macs.clear(); cc.macs.append("hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com");
        if only == 0 { cc.macs.append(",hmac-sha2-256"); }
        cc.host_key_algs.clear(); cc.host_key_algs.append("ssh-dss,ssh-ed25519");
        sc.kex.clear(); sc.kex.append(cc.kex);
        sc.ciphers.clear(); sc.ciphers.append(cc.ciphers);
        sc.macs.clear(); sc.macs.append(cc.macs);
        let r = connect(cc, sc, true);
        if only == 0 { check("unsupported names skipped", r.ok); }
        else { check("only unsupported MACs refused", !r.ok && r.msg == "no common MAC"); }
    }
}

fn authentication() {
    // Each key type, through the publickey query and signature.
    let names: const u8[:][4] = ["ed25519", "ecdsa256", "ecdsa384", "rsa2048"];
    for n in names {
        let k = if n == "ed25519" { ed25519_key() } else if n == "ecdsa256" { ecdsa_key() } else if n == "ecdsa384" { ecdsa384_key() }
                else { rsa_key() };
        var cc = client_cfg();
        let a = ssh::add_key(cc, k);
        var sc = server_cfg();
        sc.authorized_keys.append(str("# a comment\n", ssh::marshal_authorized_key(k.public, "alice's key")));
        let r = connect(cc, sc, false);
        check(str("publickey ", n), r.ok);
    }
    // A line with options is not enforced, so it lets nobody in.
    {
        let k = ed25519_key();
        let restrictions: const u8[:][3] = ["no-pty ", "restrict,command=\"false\",from=\"192.0.2.1\" ", "command=\"date\" "];
        for o in restrictions {
            var cc = client_cfg();
            let a = ssh::add_key(cc, k);
            var sc = server_cfg();
            sc.authorized_keys.append(str(o, ssh::marshal_authorized_key(k.public)));
            let r = connect(cc, sc, false);
            check(str("options refused: ", o), !r.ok && r.client_reason == ssh::DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
        }
    }
    // A key the server does not take, then one it does.
    {
        var cc = client_cfg();
        let other = ssh::generate_key(x509::KEY_ED25519);
        let good = ecdsa_key();
        let a = ssh::add_key(cc, other);
        let b = ssh::add_key(cc, good);
        var sc = server_cfg();
        sc.authorized_keys.append(ssh::marshal_authorized_key(good.public));
        let r = connect(cc, sc, false);
        check("second key", r.ok);
        var cc2 = client_cfg();
        let c2 = ssh::add_key(cc2, other);
        let r2 = connect(cc2, sc, false);
        check("no key taken", !r2.ok && r2.client_reason == ssh::DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
    }
    // Passwords: plain, keyboard-interactive, bcrypt; wrong ones; a wrong user.
    {
        var sc = server_cfg();
        let h, okh = bignum::bcrypt_hash("s3cret", 4);
        sc.passwords.append(str("alice:pw\nbob:", h, "\n"));
        var cc = client_cfg();
        ssh::set_password(cc, "pw");
        check("password", connect(cc, sc, true).ok);
        var bob = client_cfg();
        bob.user.clear();
        bob.user.append("bob");
        ssh::set_password(bob, "s3cret");
        check("bcrypt password", connect(bob, sc, false).ok);
        var wrong = client_cfg();
        ssh::set_password(wrong, "nope");
        let rw = connect(wrong, sc, false);
        check("wrong password", !rw.ok && rw.client_reason == ssh::DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
        // Keyboard-interactive only: the server lists it, the client answers.
        var kbd = client_cfg();
        ssh::set_password(kbd, "pw");
        var sc2 = server_cfg();
        sc2.passwords.append("alice:pw\n");
        var c = ssh::client(kbd);
        c.password_tried = true;             // skip "password": keyboard-interactive next
        var s = ssh::server(sc2);
        var to_server: u8[>..] = [];
        var to_client: u8[>..] = [];
        var w = seen();
        ssh::client_start(c, kbd, to_server);
        ssh::server_start(s, sc2, to_client);
        pump(c, kbd, s, sc2, to_server, to_client, w);
        check("keyboard-interactive", ssh::connected(c) && ssh::connected(s) && c.kbd_tried);
        // No password set: the client asks for one, then logs in with it.
        {
            var ask = client_cfg();
            var c2 = ssh::client(ask);
            var s2 = ssh::server(sc2);
            var ts: u8[>..] = [];
            var tc: u8[>..] = [];
            var w2 = seen();
            ssh::client_start(c2, ask, ts);
            ssh::server_start(s2, sc2, tc);
            var asked = false;
            for round in 50 {
                var sev: u8[>..] = [];
                var so: u8[>..] = [];
                let rs = ssh::server_feed(s2, sc2, ts, so, sev);
                ts.clear();
                tc.append(so);
                var cev: u8[>..] = [];
                var co: u8[>..] = [];
                let rc = ssh::client_feed(c2, ask, tc, co, cev);
                tc.clear();
                ts.append(co);
                var pos = 0;
                loop {
                    let e, ok = ssh::next_event(cev, pos);
                    if !ok { break; }
                    if e.kind == ssh::EV_PASSWORD_NEEDED {
                        asked = true;
                        let sent = ssh::client_password(c2, ask, "pw", ts);
                    }
                }
                if ts.len == 0 && tc.len == 0 { break; }
            }
            check("password asked for", asked && ssh::connected(c2) && ssh::connected(s2));
        }
        // Only one user allowed.
        var sc3 = server_cfg();
        sc3.passwords.append("alice:pw\nmallory:pw\n");
        sc3.auth_user.append("alice");
        var mal = client_cfg();
        mal.user.clear();
        mal.user.append("mallory");
        ssh::set_password(mal, "pw");
        check("other user", !connect(mal, sc3, false).ok);
        // A banner before the first reply.
        var sc4 = server_cfg();
        sc4.passwords.append("alice:pw\n");
        sc4.banner.append("Welcome\n");
        let rb = connect(cc, sc4, false);
        check("banner", rb.ok && rb.w.banner == "Welcome\n");
    }
}

fn host_keys() {
    let hk = ed25519_key();
    let other = ecdsa_key();
    var sc = server_cfg();
    sc.passwords.append("alice:pw\n");
    // Plain, hashed, a pattern, another port.
    let lines: const u8[:][4] = ["example.com", "*.com", "other.org,example.com", "!example.com,*"];
    for l in lines {
        var cc = ssh::client_config("alice", "example.com");
        ssh::set_password(cc, "pw");
        cc.known_hosts.append(str(l, " ", ssh::marshal_authorized_key(hk.public)));
        let r = connect(cc, sc, false);
        check(str("known_hosts ", l), r.ok == (l != "!example.com,*"));
    }
    var hashed = ssh::client_config("alice", "example.com");
    ssh::set_password(hashed, "pw");
    hashed.known_hosts.append(ssh::known_hosts_line(hashed, hk.public, true));
    check("hashed", connect(hashed, sc, false).ok);
    var port = ssh::client_config("alice", "example.com", 2222);
    ssh::set_password(port, "pw");
    port.known_hosts.append(str("[example.com]:2222 ", ssh::marshal_authorized_key(hk.public)));
    check("port 2222", connect(port, sc, false).ok);
    var port_wrong = ssh::client_config("alice", "example.com", 2222);
    ssh::set_password(port_wrong, "pw");
    port_wrong.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(hk.public)));
    let rpw = connect(port_wrong, sc, false);
    check("port 22's entry", !rpw.ok && rpw.msg == "host key unknown");
    // Unknown, changed, revoked, fixed.
    var unknown = ssh::client_config("alice", "example.com");
    ssh::set_password(unknown, "pw");
    let ru = connect(unknown, sc, false);
    check("unknown", !ru.ok && ru.client_reason == ssh::DISCONNECT_HOST_KEY_NOT_VERIFIABLE && ru.msg == "host key unknown");
    var changed = ssh::client_config("alice", "example.com");
    ssh::set_password(changed, "pw");
    changed.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(other.public)));
    changed.host_key_algs.clear();
    changed.host_key_algs.append("ssh-ed25519");
    let rc = connect(changed, sc, false);
    check("changed", !rc.ok && rc.msg == "host key changed");
    var revoked = client_cfg();
    ssh::set_password(revoked, "pw");
    revoked.known_hosts.append(str("@revoked * ", ssh::marshal_authorized_key(hk.public)));
    let rr = connect(revoked, sc, false);
    check("revoked", !rr.ok && rr.msg == "host key revoked");
    // Asked: the exchange waits for the application, then goes on.
    {
        var ask = ssh::client_config("alice", "example.com");
        ssh::set_password(ask, "pw");
        ask.host_key_check = ssh::HOST_KEY_ASK;
        var c = ssh::client(ask);
        var s = ssh::server(sc);
        var ts: u8[>..] = [];
        var tc: u8[>..] = [];
        var w = seen();
        ssh::client_start(c, ask, ts);
        ssh::server_start(s, sc, tc);
        var asked = 0;
        for round in 50 {
            var sev: u8[>..] = [];
            var so: u8[>..] = [];
            let rs = ssh::server_feed(s, sc, ts, so, sev);
            ts.clear();
            tc.append(so);
            var cev: u8[>..] = [];
            var co: u8[>..] = [];
            let rc = ssh::client_feed(c, ask, tc, co, cev);
            tc.clear();
            var pos = 0;
            loop {
                let e, ok = ssh::next_event(cev, pos);
                if !ok { break; }
                if e.kind == ssh::EV_HOST_KEY_UNKNOWN {
                    asked++;
                    // Nothing went out while it waited.
                    check("held", co.len == 0 && !ssh::connected(c));
                    var more: u8[>..] = [];
                    let r = ssh::host_key_accept(c, ask, co, more);
                }
            }
            ts.append(co);
            if ts.len == 0 && tc.len == 0 { break; }
        }
        check("asked", asked == 1 && ssh::connected(c) && ssh::connected(s));
        // A changed key is not asked about.
        var ask2 = ssh::client_config("alice", "example.com");
        ssh::set_password(ask2, "pw");
        ask2.host_key_check = ssh::HOST_KEY_ASK;
        ask2.known_hosts.append(str("example.com ", ssh::marshal_authorized_key(other.public)));
        ask2.host_key_algs.clear();
        ask2.host_key_algs.append("ssh-ed25519");
        let r2 = connect(ask2, sc, false);
        check("ask, changed", !r2.ok && r2.msg == "host key changed");
    }
    var fixed = ssh::client_config("alice", "example.com");
    ssh::set_password(fixed, "pw");
    fixed.host_key_check = ssh::HOST_KEY_FIXED;
    fixed.fixed_host_key.append(hk.public.blob);
    let rf = connect(fixed, sc, false);
    check("fixed", rf.ok && rf.w.host_key);
    fixed.fixed_host_key.clear();
    fixed.fixed_host_key.append(other.public.blob);
    check("fixed, other", !connect(fixed, sc, false).ok);
}

fn sessions() {
    var cc = client_cfg();
    let ed = ed25519_key();
    let a = ssh::add_key(cc, ed);
    var sc = server_cfg();
    sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    var w = seen();
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("strict kex", c.strict && s.strict);
    check("server-sig-algs", c.server_sig_algs.len > 0);
    let ch = ssh::open_session(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    let p = ssh::request_pty(c, ch, "xterm", 80, 24, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("pty", w.replies == 1);
    // 3 MB from the client: more than the window, sent as it opens.
    var big: u8[>..] = [];
    for i in 3000000 { big.push((i * 7) as! u8); }
    var sent = 0;
    for round in 100 {
        sent += ssh::channel_send(c, ch, big[sent..], to_server);
        pump(c, cc, s, sc, to_server, to_client, w);
        if sent == big.len { break; }
    }
    check("3 MB up", sent == big.len && w.got_by_server == big.len);
    // A rekey from the client, then more data under the new keys.
    let before = c.session_id;
    check("rekey", ssh::client_rekey(c, cc, to_server));
    let refused = ssh::channel_send(c, ch, "during", to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("no data during rekey", refused == 0);
    check("rekeyed", c.kex_count == 2 && s.kex_count == 2 && c.session_id == before && !c.in_kex && !s.in_kex);
    w.got_by_server = 0;
    let n = ssh::channel_send(c, ch, "after the rekey", to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("data after rekey", n == 15 && w.got_by_server == 15);
    // A rekey from the server.
    check("server rekey", ssh::server_rekey(s, sc, to_client));
    pump(c, cc, s, sc, to_server, to_client, w);
    check("rekeyed again", c.kex_count == 3 && s.kex_count == 3);
    // exec: output, stderr, exit status, close.
    let e = ssh::exec(c, ch, "uname", to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("exec", w.out == "ran: uname" && w.err == "a line on stderr\n" && w.exit == 3 && w.closed);
    // Another session; 3 MB down, through the client's window.
    w.out.clear();
    w.closed = false;
    let ch2 = ssh::open_session(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    let f = ssh::exec(c, ch2, "flood", to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    // The server sends the rest as the client's window opens.
    var down: u8[>..] = [];
    for i in 3000000 { down.push((i % 251) as! u8); }
    var done_n = w.got_by_server;
    for round in 100 {
        if done_n >= down.len { break; }
        done_n += ssh::channel_send(s, 0, down[done_n..], to_client);
        pump(c, cc, s, sc, to_server, to_client, w);
    }
    check("3 MB down", w.out.len == down.len && w.out == down);
    // Disconnect.
    ssh::disconnect(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    check("disconnect", ssh::closed(c) && ssh::closed(s) && s.reason == ssh::DISCONNECT_BY_APPLICATION);
}

// A connected client and server with a session open, the server
// rekeying after rekey_bytes.
struct Pair { c: ssh::Conn, s: ssh::Conn, ch: i64 }

fn connected(cc: const ssh::ClientConfig&, sc: const ssh::ServerConfig&, w: Seen&) -> Pair {
    var c = ssh::client(cc);
    var s = ssh::server(sc);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    ssh::client_start(c, cc, to_server);
    ssh::server_start(s, sc, to_client);
    pump(c, cc, s, sc, to_server, to_client, w);
    let ch = ssh::open_session(c, to_server);
    pump(c, cc, s, sc, to_server, to_client, w);
    return Pair { c: c, s: s, ch: ch };
}

// Rekeying counts both directions, bytes and packets, and no key carries
// 2^32 packets.
fn rekey_accounting() {
    var cc = client_cfg();
    let ed = ed25519_key();
    let a = ssh::add_key(cc, ed);
    var sc = server_cfg();
    sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
    // The server only receives (its window adjustments are small): its
    // rekey_bytes is reached by what comes in, and it rekeys (once per
    // feed, here one).
    {
        sc.rekey_bytes = 200000;
        var w = seen();
        var p = connected(cc, sc, w);
        var to_server: u8[>..] = [];
        var to_client: u8[>..] = [];
        var big: u8[>..] = [];
        big.resize(600000, 0x5a);
        var sent = 0;
        for round in 100 {
            sent += ssh::channel_send(p.c, p.ch, big[sent..], to_server);
            pump(p.c, cc, p.s, sc, to_server, to_client, w);
            if sent == big.len { break; }
        }
        check("received bytes rekey", sent == big.len && w.got_by_server == big.len && p.s.kex_count >= 2 &&
              p.c.kex_count == p.s.kex_count);
        sc.rekey_bytes = 1073741824;
    }
    // Packets: past REKEY_PACKETS received, a rekey even with rekey_bytes 0.
    {
        sc.rekey_bytes = 0;
        var w = seen();
        var p = connected(cc, sc, w);
        var to_server: u8[>..] = [];
        var to_client: u8[>..] = [];
        let n0 = p.s.kex_count;
        p.s.rx_packets = ssh::REKEY_PACKETS - 1;
        let n = ssh::channel_send(p.c, p.ch, "one more", to_server);
        pump(p.c, cc, p.s, sc, to_server, to_client, w);
        check("received packets rekey", n == 8 && p.s.kex_count == n0 + 1 && p.s.rx_packets < 100);
        sc.rekey_bytes = 1073741824;
    }
    // At MAX_PACKETS under one key, sending stops and the connection
    // fails; receiving one more fails it too.
    {
        var w = seen();
        var p = connected(cc, sc, w);
        var to_server: u8[>..] = [];
        var to_client: u8[>..] = [];
        p.c.tx_packets = ssh::MAX_PACKETS;
        let n = ssh::channel_send(p.c, p.ch, "too many", to_server);
        check("no packet past the limit", to_server.len == 0 && p.c.state == ssh::ST_FAILED &&
              p.c.reason == ssh::DISCONNECT_PROTOCOL_ERROR);
        var q = connected(cc, sc, w);
        q.s.rx_packets = ssh::MAX_PACKETS;
        let m = ssh::channel_send(q.c, q.ch, "too many", to_server);
        pump(q.c, cc, q.s, sc, to_server, to_client, w);
        check("none accepted past the limit", q.s.state == ssh::ST_FAILED && q.s.reason == ssh::DISCONNECT_PROTOCOL_ERROR);
    }
}

// A held window opens only as the server says it has used the data.
fn held_window() {
    var cc = client_cfg();
    let ed = ed25519_key();
    let a = ssh::add_key(cc, ed);
    var sc = server_cfg();
    sc.authorized_keys.append(ssh::marshal_authorized_key(ed.public));
    var w = seen();
    var p = connected(cc, sc, w);
    var to_server: u8[>..] = [];
    var to_client: u8[>..] = [];
    check("hold", ssh::channel_hold_window(p.s, 0));
    var big: u8[>..] = [];
    big.resize(4000000, 0x33);
    var sent = 0;
    for round in 20 {
        sent += ssh::channel_send(p.c, p.ch, big[sent..], to_server);
        pump(p.c, cc, p.s, sc, to_server, to_client, w);
    }
    check("held: one window and no more", sent == 2097152 && w.got_by_server == 2097152);
    ssh::channel_consumed(p.s, 0, 1048576, to_client);
    pump(p.c, cc, p.s, sc, to_server, to_client, w);
    for round in 20 {
        sent += ssh::channel_send(p.c, p.ch, big[sent..], to_server);
        pump(p.c, cc, p.s, sc, to_server, to_client, w);
    }
    check("held: as much again as was used", sent == 2097152 + 1048576 && w.got_by_server == sent);
    ssh::channel_consumed(p.s, 0, 2097152, to_client);
    pump(p.c, cc, p.s, sc, to_server, to_client, w);
    for round in 20 {
        sent += ssh::channel_send(p.c, p.ch, big[sent..], to_server);
        pump(p.c, cc, p.s, sc, to_server, to_client, w);
    }
    check("held: the rest", sent == big.len && w.got_by_server == big.len);
}

fn main() {
    algorithms();
    authentication();
    host_keys();
    sessions();
    rekey_accounting();
    held_window();
    print("conn: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
