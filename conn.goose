// ssh.conn: SSH connections, client and server, without I/O (RFC 4253's
// transport, RFC 4252's authentication, RFC 4254's channels). A Conn holds
// one connection; feed it the bytes that arrive and it appends the bytes to
// send to one builder and what happened, as events, to another:
//
//   var c = ssh::client(cfg);
//   ssh::start(c, out);                                // version and KEXINIT
//   ... send out, read into input ...
//   ssh::client_feed(c, cfg, input, out, events);       // until EV_AUTHENTICATED
//   let ch = ssh::open_session(c, out);                 // EV_CHANNEL_OPENED, then
//   ssh::exec(c, ch, "uname -a", out);                  // EV_DATA, EV_EXIT_STATUS, EV_CLOSE
//
// The transport: version exchange, KEXINIT negotiation (with the guess of
// first_kex_packet_follows), the key exchanges of ssh.kex, the host key
// checked against known_hosts lines (hashed ones too) or a fixed key,
// strict key exchange (kex-strict-*-v00@openssh.com, against Terrapin),
// server-sig-algs (RFC 8308), and rekeying on request, after rekey_bytes
// sent or received, or after 2^31 packets either way; past 2^32 - 2
// packets under one key the connection fails. Authentication: publickey (a query, then the signature),
// password and keyboard-interactive, both sides; the server checks keys
// against authorized_keys and passwords against its table (plain or
// bcrypt). Channels: sessions and any other type the application accepts,
// flow control, data and stderr, requests (exec, shell, pty-req, env,
// subsystem, exit-status, exit-signal) and their replies, EOF and close.
// Port forwarding (RFC 4254 §7): direct-tcpip channels, tcpip-forward and
// cancel-tcpip-forward requests and forwarded-tcpip channels, the
// application doing the connecting and listening.

namespace ssh;

import std;
import base64;
import ssh;
import keys;
import cipher;
import kex;
import bignum;
import bignum.hmac;
import bignum.ct;
import bignum.bcrypt;
import bignum.entropy;
import x509;

let VERSION: const u8[:] = "SSH-2.0-Goose";

// Host key algorithms, most preferred first (OpenSSH's order; ssh-rsa, SHA-1,
// last, as Go still takes it).
let HOST_KEY_ALGS: const u8[:] = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
// The signature algorithms a server takes from users (server-sig-algs).
let USER_SIG_ALGS: const u8[:] = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa";

// How a client checks the server's host key: against known_hosts lines,
// against one fixed key, or not at all (tests, and nothing else).
let HOST_KEY_KNOWN_HOSTS: i64 = 0;
let HOST_KEY_FIXED: i64 = 1;
let HOST_KEY_INSECURE: i64 = 2;
// known_hosts, but a host it does not mention is put to the application
// (EV_HOST_KEY_UNKNOWN), with the exchange held until host_key_accept.
let HOST_KEY_ASK: i64 = 3;

// Events, appended to the caller's builder: kind (u8), channel (u32), a
// value (u32) and a string of data (next_event reads them).
let EV_AUTHENTICATED: u8 = 1;          // data: the user (on the server)
let EV_BANNER: u8 = 2;                 // data: the server's banner (on the client)
let EV_CHANNEL_OPEN: u8 = 3;           // server: data: string type, then the open's extra fields; accept or reject it
let EV_CHANNEL_OPENED: u8 = 4;
let EV_CHANNEL_OPEN_FAILED: u8 = 5;    // value: the reason; data: the description
let EV_DATA: u8 = 6;
let EV_EXTENDED_DATA: u8 = 7;          // value: the type (1: stderr)
let EV_EOF: u8 = 8;
let EV_CLOSE: u8 = 9;                  // the channel is gone
let EV_REQUEST: u8 = 10;               // value: want_reply; data: string type, then its fields
let EV_REQUEST_REPLY: u8 = 11;         // value: 1 for success
let EV_EXIT_STATUS: u8 = 12;           // value: the status
let EV_EXIT_SIGNAL: u8 = 13;           // data: the signal's name
let EV_WINDOW: u8 = 14;                // the peer took more data: channel_send may send again
let EV_GLOBAL_REQUEST: u8 = 15;        // value: want_reply; data: string name, then its fields (server: answer with global_reply)
let EV_GLOBAL_REPLY: u8 = 20;          // value: 1 for success; data: the reply's fields (a port for tcpip-forward on port 0)
let EV_DISCONNECT: u8 = 16;            // value: the reason; data: the description
let EV_HOST_KEY: u8 = 17;              // client: data: the server's host key blob, once checked
let EV_HOST_KEY_UNKNOWN: u8 = 19;      // client, HOST_KEY_ASK: data: the key blob; host_key_accept or disconnect
let EV_PASSWORD_NEEDED: u8 = 18;       // client: the server takes a password and none is set: answer with client_password

// Connection states.
let ST_VERSION: i64 = 0;               // waiting for the peer's version line
let ST_KEX: i64 = 1;                   // the first key exchange
let ST_SERVICE: i64 = 2;               // client: waiting for SERVICE_ACCEPT; server: for SERVICE_REQUEST
let ST_AUTH: i64 = 3;                  // authentication
let ST_CONNECTED: i64 = 4;             // authenticated: channels
let ST_CLOSED: i64 = 5;                // a DISCONNECT was sent or received
let ST_FAILED: i64 = 6;                // an error: c.reason and c.message say what

// Channel states.
let CH_FREE: i64 = 0;
let CH_OPENING: i64 = 1;               // we asked to open it
let CH_PEER_OPENING: i64 = 2;          // the peer asked; the application decides
let CH_OPEN: i64 = 3;

// The window we give each channel and the largest packet we take
// (Go's: 64 packets of 32 KB).
let CHANNEL_WINDOW: u32 = 2097152;
let CHANNEL_MAX_PACKET: u32 = 32768;
let MAX_CHANNELS: i64 = 64;

// What a client needs: the user, the host (and port) it connects to, for
// the host key check; its keys and password; how to check the host key,
// with known_hosts lines or the one key; the algorithms in order of
// preference; its version string; and after how many bytes to rekey (Go's
// 1 GB by default).
struct ClientConfig {
    user: u8[..255], host: u8[..255], port: i64,
    keys: PrivateKey[..4], password: u8[..256], has_password: bool,
    host_key_check: i64, known_hosts: u8[..65536], fixed_host_key: u8[..2200],
    kex: u8[..1024], host_key_algs: u8[..512], ciphers: u8[..512], macs: u8[..512],
    version: u8[..255], rekey_bytes: i64,
}

fn client_config(user: const u8[:], host: const u8[:], port: i64 = 22) -> ClientConfig {
    var c = ClientConfig {
        user: [], host: [], port: port, keys: [], password: [], has_password: false,
        host_key_check: HOST_KEY_KNOWN_HOSTS, known_hosts: [], fixed_host_key: [],
        kex: [], host_key_algs: [], ciphers: [], macs: [], version: [], rekey_bytes: 1073741824,
    };
    c.user.append(user);
    c.host.append(host);
    c.kex.append(KEX_DEFAULT);
    c.host_key_algs.append(HOST_KEY_ALGS);
    c.ciphers.append(CIPHERS);
    c.macs.append(MACS);
    c.version.append(VERSION);
    return c;
}

fn add_key(cfg: ClientConfig&, k: const PrivateKey&) -> bool {
    if cfg.keys.len == cfg.keys.cap { return false; }
    cfg.keys.push(k);
    return true;
}

fn set_password(cfg: ClientConfig&, pw: const u8[:]) {
    cfg.password.clear();
    cfg.password.append(pw);
    cfg.has_password = true;
}

// What a server needs: its host keys (one per type), whom it lets in (the
// authorized_keys lines; "user:password" lines, a password plain or a
// bcrypt hash; only `auth_user` if set; everyone with no_client_auth), how
// many failed attempts it takes (Go's 6), a banner, the algorithms, its
// version and when to rekey.
struct ServerConfig {
    host_keys: PrivateKey[..4],
    authorized_keys: u8[..65536], passwords: u8[..8192], auth_user: u8[..255], no_client_auth: bool,
    max_auth_tries: i64, banner: u8[..1024],
    kex: u8[..1024], ciphers: u8[..512], macs: u8[..512], version: u8[..255], rekey_bytes: i64,
}

fn server_config() -> ServerConfig {
    var s = ServerConfig {
        host_keys: [], authorized_keys: [], passwords: [], auth_user: [], no_client_auth: false, max_auth_tries: 6,
        banner: [], kex: [], ciphers: [], macs: [], version: [], rekey_bytes: 1073741824,
    };
    s.kex.append(KEX_DEFAULT);
    s.ciphers.append(CIPHERS);
    s.macs.append(MACS);
    s.version.append(VERSION);
    return s;
}

fn add_host_key(cfg: ServerConfig&, k: const PrivateKey&) -> bool {
    if cfg.host_keys.len == cfg.host_keys.cap { return false; }
    cfg.host_keys.push(k);
    return true;
}

// One channel: our number is its index; the peer's number, the windows
// both ways (what we still take, what the peer still takes), the largest
// packet the peer takes, its type, how far its close has gone, and how
// many of the peer's requests await a reply.
// held: the window opens again only as the application says it has used
// the data (channel_consumed), not as the data arrives; consumed counts
// what it has used since the last WINDOW_ADJUST.
struct Channel {
    state: i64, remote: u32, in_window: u32, out_window: u32, out_max: u32,
    sent_eof: bool, sent_close: bool, recv_eof: bool, recv_close: bool, replies: i64,
    held: bool, consumed: u32,
}

fn free_channel() -> Channel {
    Channel { state: CH_FREE, remote: 0, in_window: 0, out_window: 0, out_max: 0, sent_eof: false, sent_close: false,
              recv_eof: false, recv_close: false, replies: 0, held: false, consumed: 0 }
}

// Authentication's steps, on the client.
let AUTH_NONE: i64 = 0;                // "none" sent, to learn the methods
let AUTH_PK_QUERY: i64 = 1;            // a key offered without a signature
let AUTH_PK_SIGNED: i64 = 2;
let AUTH_PASSWORD: i64 = 3;
let AUTH_KBD: i64 = 4;
let AUTH_WAIT_PASSWORD: i64 = 5;       // EV_PASSWORD_NEEDED given, waiting for client_password

// One connection, either side.
struct Conn {
    is_server: bool, state: i64,
    reason: u32,                      // the disconnect reason of a failure, or the peer's
    message: u8[..256],               // what went wrong
    my_version: u8[..255], peer_version: u8[..255],
    my_kexinit: u8[..4096], peer_kexinit: u8[..8192],
    // The negotiated algorithms.
    kex_name: u8[..64], host_key_alg: u8[..64], cipher_c2s: u8[..64], cipher_s2c: u8[..64],
    mac_c2s: u8[..64], mac_s2c: u8[..64],
    kx: Kex, session_id: u8[..64], host_key: PublicKey,
    strict: bool,                     // strict key exchange: sequence numbers restart at each NEWKEYS
    peer_ext_info: bool,              // the peer takes EXT_INFO
    server_sig_algs: u8[..1024],      // client: what the server's EXT_INFO named
    in_kex: bool, sent_kexinit: bool, sent_newkeys: bool, kex_count: i64,
    ignore_next: bool,                // the peer guessed its first kex packet wrong
    tx: PacketCipher, rx: PacketCipher, tx_next: PacketCipher, rx_next: PacketCipher,
    tx_bytes: i64, tx_packets: i64,        // sent under the current keys
    rx_bytes: i64, rx_packets: i64,        // received under the current keys
    user: u8[..255],
    auth_step: i64, key_index: i64, password_tried: bool, kbd_tried: bool, auth_tries: i64, kbd_pending: bool,
    banner_sent: bool,
    password: u8[..256], has_password: bool,   // the client's, from the config or client_password
    // HOST_KEY_ASK: the exchange held for the application, with what
    // finishing it needs.
    host_key_wait: bool, held_k: u8[..2200], held_h: u8[..64],
    auth_methods: u8[..256],                   // what the server's last failure allowed
    global_replies: i64,                       // the peer's global requests awaiting the application's reply
    channels: Channel[..64],
    deferred: u8[..65536],                     // messages held during our key exchange (send_packet)
    inbuf: u8[..270000],
}

fn new_conn(is_server: bool) -> Conn {
    let kx, ok = kex_method("curve25519-sha256");
    var c = Conn {
        is_server: is_server, state: ST_VERSION, reason: 0, message: [], my_version: [], peer_version: [],
        my_kexinit: [], peer_kexinit: [], kex_name: [], host_key_alg: [], cipher_c2s: [], cipher_s2c: [],
        mac_c2s: [], mac_s2c: [], kx: kx, session_id: [], host_key: no_public_key(), strict: false,
        peer_ext_info: false, server_sig_algs: [], in_kex: false, sent_kexinit: false, sent_newkeys: false,
        kex_count: 0, ignore_next: false, tx: no_cipher(), rx: no_cipher(), tx_next: no_cipher(), rx_next: no_cipher(),
        tx_bytes: 0, tx_packets: 0, rx_bytes: 0, rx_packets: 0, user: [], auth_step: AUTH_NONE, key_index: 0, password_tried: false, kbd_tried: false,
        auth_tries: 0, kbd_pending: false, banner_sent: false, password: [], has_password: false, host_key_wait: false, held_k: [], held_h: [],
        auth_methods: [], global_replies: 0, channels: [], deferred: [], inbuf: [],
    };
    for i in MAX_CHANNELS { c.channels.push(free_channel()); }
    return c;
}

fn client(cfg: const ClientConfig&) -> Conn {
    var c = new_conn(false);
    c.my_version.append(cfg.version);
    c.user.append(cfg.user);
    c.password.append(cfg.password);
    c.has_password = cfg.has_password;
    return c;
}

fn server(cfg: const ServerConfig&) -> Conn {
    var c = new_conn(true);
    c.my_version.append(cfg.version);
    return c;
}

fn connected(c: const Conn&) -> bool { c.state == ST_CONNECTED }
fn failed(c: const Conn&) -> bool { c.state == ST_FAILED }
fn closed(c: const Conn&) -> bool { c.state == ST_CLOSED || c.state == ST_FAILED }

// --- Events -----------------------------------------------------------------------

fn event(events: u8[>..]&, kind: u8, ch: i64, value: u32, data: const u8[:]) {
    events.push(kind);
    put_u32(events, ch as! u32);
    put_u32(events, value);
    put_string(events, data);
}

// One event as next_event reads it: the data as offsets into the events.
struct Event { kind: u8, channel: i64, value: u32, data: Rd }

// The event at pos, which moves past it; false at the end.
fn next_event(events: const u8[:], pos: i64&) -> Event, bool {
    var r = rd_at(pos, events.len);
    let kind = get_u8(r, events);
    let ch = get_u32(r, events);
    let v = get_u32(r, events);
    let d = get_string(r, events);
    if r.bad { return Event { kind: 0, channel: 0, value: 0, data: empty_rd() }, false; }
    pos = r.pos;
    let chn: i64 = ch;
    return Event { kind: kind, channel: chn, value: v, data: d }, true;
}

// --- Sending ----------------------------------------------------------------------

// Packets under one key, each direction: a rekey starts at REKEY_PACKETS
// whatever rekey_bytes says (Go's packetRekeyThreshold), and the
// connection fails rather than go past MAX_PACKETS, short of 2^32: the
// sequence number would come back, and ChaCha20-Poly1305's nonce is the
// sequence number.
let REKEY_PACKETS: i64 = 2147483648;
let MAX_PACKETS: i64 = 4294967294;

// Whether a message may go while our KEXINIT waits for our NEWKEYS: the
// transport's generic messages but SERVICE_REQUEST and SERVICE_ACCEPT, and
// the key exchange's own (RFC 4253 §7.1).
fn kex_may_send(t: u8) -> bool { (t >= 1 && t <= 19 && t != MSG_SERVICE_REQUEST && t != MSG_SERVICE_ACCEPT) || (t >= 20 && t <= 49) }

fn send_packet(c: Conn&, payload: const u8[:], out: u8[>..]&) {
    // Between our KEXINIT and our NEWKEYS anything else waits, in order, and
    // goes once NEWKEYS has (flush_deferred); too much waiting fails the
    // connection rather than lose a message.
    if c.sent_kexinit && !c.sent_newkeys && payload.len > 0 && !kex_may_send(payload[0]) {
        if c.deferred.len + 4 + payload.len > c.deferred.cap {
            let msg = "too much to send during a key exchange";
            var b: u8[>..] = [];
            b.push(MSG_DISCONNECT);
            put_u32(b, DISCONNECT_PROTOCOL_ERROR);
            put_string(b, msg);
            put_string(b, "");
            seal_out(c, b, out);
            c.reason = DISCONNECT_PROTOCOL_ERROR;
            c.message.clear();
            c.message.append(msg);
            c.state = ST_FAILED;
            return;
        }
        let n = payload.len;
        let len: u8[4] = [(n >> 24) as! u8, (n >> 16) as! u8, (n >> 8) as! u8, n as! u8];
        c.deferred.append(len);
        c.deferred.append(payload);
        return;
    }
    seal_out(c, payload, out);
}

// A packet under the current keys, counted; none past MAX_PACKETS.
fn seal_out(c: Conn&, payload: const u8[:], out: u8[>..]&) {
    if c.tx_packets >= MAX_PACKETS {
        if c.state != ST_FAILED && c.state != ST_CLOSED {
            c.reason = DISCONNECT_PROTOCOL_ERROR;
            c.message.clear();
            c.message.append("too many packets under one key");
            c.state = ST_FAILED;
        }
        return;
    }
    let before = out.len;
    out.append(seal_packet(c.tx, payload));
    c.tx_bytes += out.len - before;
    c.tx_packets++;
}

// The messages held during the key exchange, under the new keys.
fn flush_deferred(c: Conn&, out: u8[>..]&) {
    var held: u8[>..] = [];
    held.append(c.deferred);
    c.deferred.clear();
    var pos = 0;
    while pos + 4 <= held.len {
        let n = ((held[pos] as i64) << 24) | ((held[pos + 1] as i64) << 16) | ((held[pos + 2] as i64) << 8) | held[pos + 3];
        seal_out(c, held[pos + 4..pos + 4 + n], out);
        pos += 4 + n;
    }
}

// Fails the connection: a DISCONNECT, if the version lines are done, and
// the reason kept.
fn fail(c: Conn&, reason: u32, msg: const u8[:], out: u8[>..]&) -> i64 {
    if c.state == ST_FAILED || c.state == ST_CLOSED { return -1; }
    if c.state != ST_VERSION {
        var b: u8[>..] = [];
        b.push(MSG_DISCONNECT);
        put_u32(b, reason);
        put_string(b, msg);
        put_string(b, "");
        send_packet(c, b, out);
    }
    c.reason = reason;
    c.message.clear();
    c.message.append(msg[..::min(msg.len, 256)]);
    c.state = ST_FAILED;
    return -1;
}

// Ends the connection with DISCONNECT_BY_APPLICATION.
fn disconnect(c: Conn&, out: u8[>..]&) {
    if c.state == ST_FAILED || c.state == ST_CLOSED || c.state == ST_VERSION { return; }
    var b: u8[>..] = [];
    b.push(MSG_DISCONNECT);
    put_u32(b, DISCONNECT_BY_APPLICATION);
    put_string(b, "bye");
    put_string(b, "");
    send_packet(c, b, out);
    c.state = ST_CLOSED;
}

// The version line, then KEXINIT, without waiting for the peer's.
fn start(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, out: u8[>..]&) {
    out.append(c.my_version);
    out.append("\r\n");
    send_kexinit(c, ccfg, scfg, out);
}

fn client_start(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&) {
    let none = no_server();
    start(c, cfg, none, out);
}

fn server_start(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) {
    let none = no_client();
    start(c, none, cfg, out);
}

// --- Key exchange -------------------------------------------------------------------

// The host key algorithms a server can sign with, for its keys.
fn server_host_key_algs(cfg: const ServerConfig&) -> u8[>..] {
    var out: u8[>..] = [];
    for k in cfg.host_keys {
        if k.key.kind == x509::KEY_RSA {
            add_name(out, SIG_RSA_SHA512);
            add_name(out, SIG_RSA_SHA256);
            add_name(out, SIG_RSA_SHA1);
        } else {
            add_name(out, key_type(k.key.kind));
        }
    }
    return out;
}

// The client's host key algorithms: the configured order, with those of
// keys known_hosts has for this host first (as OpenSSH orders them), so
// the server picks a key the client can check.
fn client_host_key_algs(cfg: const ClientConfig&) -> u8[>..] {
    var known: u8[>..] = [];
    var other: u8[>..] = [];
    var i = 0;
    let list = cfg.host_key_algs[..];
    while i < list.len {
        var j = i;
        while j < list.len && list[j] != ',' { j++; }
        let alg = list[i..j];
        if j > i && has_name(HOST_KEY_ALGS, alg) {
            if cfg.host_key_check == HOST_KEY_KNOWN_HOSTS && known_kind(cfg, kind_of_sig(alg)) { add_name(known, alg); }
            else { add_name(other, alg); }
        }
        i = j + 1;
    }
    if other.len > 0 { add_name(known, other); }
    return known;
}

fn send_kexinit(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, out: u8[>..]&) {
    var b: u8[>..] = [];
    b.push(MSG_KEXINIT);
    var cookie: u8[16] = [0; 16];
    bignum::random_bytes(cookie);
    b.append(cookie);
    // The kex list carries the extension and strict-kex markers on the
    // first exchange only. Each list offers only what this package has.
    var kexl = supported_names(if c.is_server { scfg.kex[..] } else { ccfg.kex[..] }, KEX_SUPPORTED);
    if c.kex_count == 0 {
        add_name(kexl, if c.is_server { "ext-info-s" } else { "ext-info-c" });
        add_name(kexl, if c.is_server { "kex-strict-s-v00@openssh.com" } else { "kex-strict-c-v00@openssh.com" });
    }
    put_string(b, kexl);
    if c.is_server { put_string(b, server_host_key_algs(scfg)); } else { put_string(b, client_host_key_algs(ccfg)); }
    let ciphers = supported_names(if c.is_server { scfg.ciphers[..] } else { ccfg.ciphers[..] }, CIPHERS);
    let macs = supported_names(if c.is_server { scfg.macs[..] } else { ccfg.macs[..] }, MACS);
    put_string(b, ciphers);
    put_string(b, ciphers);
    put_string(b, macs);
    put_string(b, macs);
    put_string(b, "none");
    put_string(b, "none");
    put_string(b, "");
    put_string(b, "");
    put_bool(b, false);
    put_u32(b, 0);
    c.my_kexinit.clear();
    c.my_kexinit.append(b);
    send_packet(c, b, out);
    c.sent_kexinit = true;
    c.in_kex = true;
}

// A rekey: a new KEXINIT; the exchange then runs as the first did, under
// the old keys, the session ID unchanged.
fn rekey(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, out: u8[>..]&) -> bool {
    if c.state != ST_CONNECTED || c.in_kex { return false; }
    send_kexinit(c, ccfg, scfg, out);
    return true;
}

// The ten name-lists of a KEXINIT (offsets into m), and the guess flag.
struct KexLists { kex: Rd, host: Rd, enc_cs: Rd, enc_sc: Rd, mac_cs: Rd, mac_sc: Rd, comp_cs: Rd, comp_sc: Rd, follows: bool }

fn parse_kexinit(m: const u8[:]) -> KexLists, bool {
    var r = rd_at(17, m.len);
    let l = KexLists { kex: get_string(r, m), host: get_string(r, m), enc_cs: get_string(r, m), enc_sc: get_string(r, m),
                       mac_cs: get_string(r, m), mac_sc: get_string(r, m), comp_cs: get_string(r, m),
                       comp_sc: get_string(r, m), follows: false };
    let lang1 = get_string(r, m);
    let lang2 = get_string(r, m);
    let f = get_bool(r, m);
    let reserved = get_u32(r, m);
    if r.bad || m.len < 17 { return l, false; }
    var l2 = l;
    l2.follows = f;
    return l2, true;
}

// Both KEXINITs are in: the algorithms, each the client's first that the
// server has (RFC 4253 §7.1).
fn negotiate_all(c: Conn&, out: u8[>..]&) -> i64 {
    let mine, ok1 = parse_kexinit(c.my_kexinit);
    let theirs, ok2 = parse_kexinit(c.peer_kexinit);
    if !ok1 || !ok2 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad KEXINIT", out); }
    let cl = if c.is_server { theirs } else { mine };
    let sl = if c.is_server { mine } else { theirs };
    let cm = if c.is_server { c.peer_kexinit[..] } else { c.my_kexinit[..] };
    let sm = if c.is_server { c.my_kexinit[..] } else { c.peer_kexinit[..] };
    let kexn = negotiate(bytes(cm, cl.kex), bytes(sm, sl.kex));
    let hostn = negotiate(bytes(cm, cl.host), bytes(sm, sl.host));
    let ecs = negotiate(bytes(cm, cl.enc_cs), bytes(sm, sl.enc_cs));
    let esc = negotiate(bytes(cm, cl.enc_sc), bytes(sm, sl.enc_sc));
    let comp1 = negotiate(bytes(cm, cl.comp_cs), bytes(sm, sl.comp_cs));
    let comp2 = negotiate(bytes(cm, cl.comp_sc), bytes(sm, sl.comp_sc));
    if kexn.len == 0 || kexn == "ext-info-c" || kexn.starts_with("kex-strict-") || hostn.len == 0 || ecs.len == 0 ||
       esc.len == 0 || comp1 != "none" || comp2 != "none" {
        return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no common algorithm", out);
    }
    var mcs: u8[>..] = [];
    var msc: u8[>..] = [];
    if !is_aead(ecs) { mcs = negotiate(bytes(cm, cl.mac_cs), bytes(sm, sl.mac_cs)); }
    if !is_aead(esc) { msc = negotiate(bytes(cm, cl.mac_sc), bytes(sm, sl.mac_sc)); }
    if (!is_aead(ecs) && mcs.len == 0) || (!is_aead(esc) && msc.len == 0) {
        return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no common MAC", out);
    }
    let kx, okk = kex_method(kexn);
    if !okk { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no common key exchange", out); }
    c.kx = kx;
    c.kex_name.clear(); c.kex_name.append(kexn);
    c.host_key_alg.clear(); c.host_key_alg.append(hostn);
    c.cipher_c2s.clear(); c.cipher_c2s.append(ecs);
    c.cipher_s2c.clear(); c.cipher_s2c.append(esc);
    c.mac_c2s.clear(); c.mac_c2s.append(mcs);
    c.mac_s2c.clear(); c.mac_s2c.append(msc);
    if c.kex_count == 0 {
        let peer_kex = bytes(c.peer_kexinit, theirs.kex);
        c.strict = has_name(peer_kex, if c.is_server { "kex-strict-c-v00@openssh.com" } else { "kex-strict-s-v00@openssh.com" });
        c.peer_ext_info = c.is_server && has_name(peer_kex, "ext-info-c");
    }
    // A wrong guess: the peer's first kex packet is dropped (§7).
    if theirs.follows {
        let guess_kex = first_name(bytes(c.peer_kexinit, theirs.kex));
        let guess_host = first_name(bytes(c.peer_kexinit, theirs.host));
        if guess_kex != kexn || guess_host != hostn { c.ignore_next = true; }
    }
    return 0;
}

fn on_kexinit(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if c.in_kex && c.peer_kexinit.len > 0 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "KEXINIT twice", out); }
    // Strict: KEXINIT must be the first packet of the connection.
    if m.len > c.peer_kexinit.cap { return fail(c, DISCONNECT_PROTOCOL_ERROR, "KEXINIT too long", out); }
    c.peer_kexinit.clear();
    c.peer_kexinit.append(m);
    if !c.sent_kexinit { send_kexinit(c, ccfg, scfg, out); }
    if negotiate_all(c, out) != 0 { return -1; }
    if c.kex_count == 0 && c.strict && c.rx.seq != 1 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "strict KEX: KEXINIT not first", out); }
    if !c.is_server {
        kex_keygen(c.kx);
        var b: u8[>..] = [];
        b.push(MSG_KEX_ECDH_INIT);
        put_kex_value(b, c.kx, c.kx.mine);
        send_packet(c, b, out);
    }
    return 0;
}

// The keys for the next NEWKEYS, from K and H (RFC 4253 §7.2).
fn derive_ciphers(c: Conn&, k_enc: const u8[:], h: const u8[:]) {
    let hash = c.kx.hash;
    let sid = c.session_id[..];
    let kl1, il1, ok1 = cipher_sizes(c.cipher_c2s);
    let kl2, il2, ok2 = cipher_sizes(c.cipher_s2c);
    let h1, ml1, e1, okm1 = mac_sizes(c.mac_c2s);
    let h2, ml2, e2, okm2 = mac_sizes(c.mac_s2c);
    let iv_cs = derive_key(hash, k_enc, h, 'A', sid, il1);
    let iv_sc = derive_key(hash, k_enc, h, 'B', sid, il2);
    let key_cs = derive_key(hash, k_enc, h, 'C', sid, kl1);
    let key_sc = derive_key(hash, k_enc, h, 'D', sid, kl2);
    let mac_cs = derive_key(hash, k_enc, h, 'E', sid, ml1);
    let mac_sc = derive_key(hash, k_enc, h, 'F', sid, ml2);
    let cs = packet_cipher(c.cipher_c2s, c.mac_c2s, key_cs, iv_cs, mac_cs);
    let sc = packet_cipher(c.cipher_s2c, c.mac_s2c, key_sc, iv_sc, mac_sc);
    if c.is_server { c.tx_next = sc; c.rx_next = cs; } else { c.tx_next = cs; c.rx_next = sc; }
}

fn send_newkeys(c: Conn&, out: u8[>..]&) {
    let b: u8[1] = [MSG_NEWKEYS];
    send_packet(c, b, out);
    let seq = c.tx.seq;
    c.tx = c.tx_next;
    c.tx.seq = if c.strict { 0 } else { seq };
    c.tx_bytes = 0;
    c.tx_packets = 0;
    c.sent_newkeys = true;
    flush_deferred(c, out);
}

// The server: the client's public value; it answers with its host key,
// its public value and the signature of H, then NEWKEYS.
fn server_kex_init(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    var r = rd_at(1, m.len);
    var theirs = empty_rd();
    if c.kx.method == KEX_DH {
        let e, ok = get_mpint(r, m);
        if !ok { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad e", out); }
        theirs = e;
    } else {
        theirs = get_string(r, m);
    }
    if !done(r) { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad KEX init", out); }
    let k_enc, ok = kex_server_secret(c.kx, bytes(m, theirs));
    if !ok { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "bad public value", out); }
    // The host key for the negotiated algorithm.
    var hk = -1;
    for i in cfg.host_keys.len { if hk < 0 && sig_fits(cfg.host_keys[i].key.kind, c.host_key_alg) { hk = i; } }
    if hk < 0 { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "no host key", out); }
    let key = cfg.host_keys[hk];
    let ic = c.peer_kexinit[..];
    let is = c.my_kexinit[..];
    let h = exchange_hash(c.kx, c.peer_version, c.my_version, ic, is, key.public.blob, bytes(m, theirs), c.kx.mine, k_enc);
    if c.session_id.len == 0 { c.session_id.append(h); }
    var b: u8[>..] = [];
    b.push(MSG_KEX_ECDH_REPLY);
    put_string(b, key.public.blob);
    put_kex_value(b, c.kx, c.kx.mine);
    let sig, oks = sign(key, c.host_key_alg, h);
    if !oks { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "host key signing failed", out); }
    put_string(b, sig);
    send_packet(c, b, out);
    derive_ciphers(c, k_enc, h);
    send_newkeys(c, out);
    return 0;
}

// The client: the server's reply; its host key is checked, then the
// signature over H; then NEWKEYS.
fn client_kex_reply(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    var r = rd_at(1, m.len);
    let ks = get_string(r, m);
    var theirs = empty_rd();
    if c.kx.method == KEX_DH {
        let f, ok = get_mpint(r, m);
        if !ok { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad f", out); }
        theirs = f;
    } else {
        theirs = get_string(r, m);
    }
    let sig = get_string(r, m);
    if !done(r) { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad KEX reply", out); }
    let hk, okh = parse_public_key(bytes(m, ks));
    if !okh || !sig_fits(hk.kind, c.host_key_alg) { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "bad host key", out); }
    // A rekey must keep the host key.
    if c.kex_count > 0 && hk.blob[..] != c.host_key.blob[..] {
        return fail(c, DISCONNECT_HOST_KEY_NOT_VERIFIABLE, "host key changed in a rekey", out);
    }
    var ask = false;
    if c.kex_count == 0 {
        let e = check_host_key(cfg, hk);
        ask = cfg.host_key_check == HOST_KEY_ASK && e == "host key unknown";
        if e.len > 0 && !ask { return fail(c, DISCONNECT_HOST_KEY_NOT_VERIFIABLE, e, out); }
    }
    let k_enc, ok = kex_client_secret(c.kx, bytes(m, theirs));
    if !ok { return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "bad public value", out); }
    let h = exchange_hash(c.kx, c.my_version, c.peer_version, c.my_kexinit, c.peer_kexinit, bytes(m, ks), c.kx.mine,
                          bytes(m, theirs), k_enc);
    if !verify(hk, c.host_key_alg, h, bytes(m, sig)) {
        return fail(c, DISCONNECT_KEY_EXCHANGE_FAILED, "bad host key signature", out);
    }
    if c.kex_count == 0 { c.host_key = hk; }
    if ask {
        // Held: the server's NEWKEYS and anything after it wait in inbuf.
        c.host_key_wait = true;
        c.held_k.clear();
        c.held_k.append(k_enc);
        c.held_h.clear();
        c.held_h.append(h);
        event(events, EV_HOST_KEY_UNKNOWN, 0, 0, hk.blob);
        return 0;
    }
    if c.kex_count == 0 { event(events, EV_HOST_KEY, 0, 0, hk.blob); }
    if c.session_id.len == 0 { c.session_id.append(h); }
    derive_ciphers(c, k_enc, h);
    send_newkeys(c, out);
    return 0;
}

// The application trusts the host key of EV_HOST_KEY_UNKNOWN: the exchange
// goes on, and what arrived meanwhile is handled.
fn host_key_accept(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&, events: u8[>..]&) -> i64 {
    if !c.host_key_wait { return -1; }
    c.host_key_wait = false;
    event(events, EV_HOST_KEY, 0, 0, c.host_key.blob);
    var h: u8[>..] = [];
    h.append(c.held_h);
    if c.session_id.len == 0 { c.session_id.append(h); }
    var k: u8[>..] = [];
    k.append(c.held_k);
    derive_ciphers(c, k, h);
    send_newkeys(c, out);
    return client_feed(c, cfg, "", out, events);
}

// The peer's NEWKEYS: its new keys from here on. With both sent, the
// exchange is done: the first one goes on to authentication (and the
// server's EXT_INFO).
fn on_newkeys(c: Conn&, scfg: const ServerConfig&, m: const u8[:], out: u8[>..]&) -> i64 {
    if !c.in_kex || !c.sent_newkeys || m.len != 1 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected NEWKEYS", out); }
    let seq = c.rx.seq;
    c.rx = c.rx_next;
    c.rx.seq = if c.strict { 0 } else { seq };
    c.in_kex = false;
    c.sent_kexinit = false;
    c.sent_newkeys = false;
    c.peer_kexinit.clear();
    c.rx_bytes = 0;
    c.rx_packets = 0;
    c.kex_count++;
    if c.kex_count == 1 {
        c.state = ST_SERVICE;
        if c.is_server && c.peer_ext_info {
            var b: u8[>..] = [];
            b.push(MSG_EXT_INFO);
            put_u32(b, 1);
            put_string(b, "server-sig-algs");
            put_string(b, USER_SIG_ALGS);
            send_packet(c, b, out);
        }
        if !c.is_server {
            var b: u8[>..] = [];
            b.push(MSG_SERVICE_REQUEST);
            put_string(b, "ssh-userauth");
            send_packet(c, b, out);
        }
    }
    return 0;
}

// --- Host keys ------------------------------------------------------------------------

// The name known_hosts has for the client's host: "host", or "[host]:port"
// off port 22.
fn known_host_name(cfg: const ClientConfig&) -> u8[>..] {
    var out: u8[>..] = [];
    if cfg.port == 22 { out.append(cfg.host); return out; }
    out.push('[');
    out.append(cfg.host);
    out.append("]:");
    format_int(out, cfg.port, 10, 0, ' ');
    return out;
}

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// Whether a glob pattern (* and ?) matches a name, case-insensitively: the
// usual loop, going back to the last * on a mismatch.
fn glob_match(pat: const u8[:], name: const u8[:]) -> bool {
    var p = 0;
    var n = 0;
    var star = -1;
    var mark = 0;
    while n < name.len {
        if p < pat.len && (pat[p] == '?' || (pat[p] != '*' && lower(pat[p]) == lower(name[n]))) {
            p++;
            n++;
        } else if p < pat.len && pat[p] == '*' {
            star = p;
            mark = n;
            p++;
        } else if star >= 0 {
            p = star + 1;
            mark++;
            n = mark;
        } else {
            return false;
        }
    }
    while p < pat.len && pat[p] == '*' { p++; }
    return p == pat.len;
}

// Whether a known_hosts host field (patterns, comma-separated, ! negates;
// or one hashed entry, |1|salt|hash) names a host.
fn hosts_match(field: const u8[:], name: const u8[:]) -> bool {
    if field.starts_with("|1|") {
        let rest = field[3..];
        var bar = 0;
        while bar < rest.len && rest[bar] != '|' { bar++; }
        var salt: u8[>..] = [];
        var want: u8[>..] = [];
        if bar == rest.len || !base64::decode(salt, rest[..bar]) || !base64::decode(want, rest[bar + 1..]) { return false; }
        let got = bignum::hmac(160, salt, name);
        return got.len == want.len && bignum::ct_eq_bytes(got, want) == 1;
    }
    var matched = false;
    var i = 0;
    while i < field.len {
        var j = i;
        while j < field.len && field[j] != ',' { j++; }
        let p = field[i..j];
        if p.len > 0 && p[0] == '!' {
            if glob_match(p[1..], name) { return false; }
        } else if glob_match(p, name) {
            matched = true;
        }
        i = j + 1;
    }
    return matched;
}

// What known_hosts says of a host key: 1 known, 0 not mentioned, -1 the host
// is there with other keys only, -2 revoked. Lines: [@revoked |
// @cert-authority] hosts keytype key [comment]; @cert-authority lines are
// for certificates, which this package does not take.
fn known_host_status(cfg: const ClientConfig&, k: const PublicKey&) -> i64 {
    let name = known_host_name(cfg);
    // A revocation wins wherever it is.
    for line in split(cfg.known_hosts, '\n') {
        let w = words(line);
        if w.len < 3 || w[0] != "@revoked" { continue; }
        var blob: u8[>..] = [];
        if base64::decode(blob, w[if w.len >= 4 { 3 } else { 2 }]) && blob[..] == k.blob[..] { return -2; }
    }
    var seen = false;
    for line in split(cfg.known_hosts, '\n') {
        let w = words(line);
        if w.len < 3 || w[0].starts_with("#") { continue; }
        var at = 0;
        var revoked = false;
        if w[0] == "@revoked" { revoked = true; at = 1; }
        else if w[0].starts_with("@") { continue; }
        if w.len < at + 3 { continue; }
        var blob: u8[>..] = [];
        if !base64::decode(blob, w[at + 2]) { continue; }
        if revoked { continue; }
        if !hosts_match(w[at], name) { continue; }
        if blob[..] == k.blob[..] { return 1; }
        seen = true;
    }
    return if seen { -1 } else { 0 };
}

// Whether known_hosts has a key of this kind for the host.
fn known_kind(cfg: const ClientConfig&, kind: i64) -> bool {
    let name = known_host_name(cfg);
    for line in split(cfg.known_hosts, '\n') {
        let w = words(line);
        if w.len < 3 || w[0].starts_with("#") || w[0].starts_with("@") { continue; }
        if kind_of_type(w[1]) == kind && hosts_match(w[0], name) { return true; }
    }
    return false;
}

// Why a host key is refused; empty when it is accepted.
fn check_host_key(cfg: const ClientConfig&, k: const PublicKey&) -> u8[>..] {
    var e: u8[>..] = [];
    if cfg.host_key_check == HOST_KEY_INSECURE { return e; }
    if cfg.host_key_check == HOST_KEY_FIXED {
        if cfg.fixed_host_key[..] != k.blob[..] { e.append("host key mismatch"); }
        return e;
    }
    let s = known_host_status(cfg, k);
    if s == 0 { e.append("host key unknown"); }
    else if s == -1 { e.append("host key changed"); }
    else if s == -2 { e.append("host key revoked"); }
    return e;
}

// A known_hosts line for a host and key (hashed, as HashKnownHosts writes
// it, with hash), to add once the user trusts it.
fn known_hosts_line(cfg: const ClientConfig&, k: const PublicKey&, hash: bool) -> u8[>..] {
    var out: u8[>..] = [];
    let name = known_host_name(cfg);
    if hash {
        var salt: u8[20] = [0; 20];
        bignum::random_bytes(salt);
        out.append("|1|");
        base64::encode(out, salt);
        out.push('|');
        base64::encode(out, bignum::hmac(160, salt, name));
    } else {
        out.append(name);
    }
    out.push(' ');
    out.append(marshal_authorized_key(k));
    return out;
}

// --- Authentication: the client ---------------------------------------------------------

// The signature algorithm for a user key: for RSA the strongest the server
// lists in server-sig-algs (rsa-sha2-512 without the extension, as Go).
fn user_sig_alg(c: const Conn&, k: const PrivateKey&) -> const u8[:] {
    if k.key.kind != x509::KEY_RSA { return key_type(k.key.kind); }
    if c.server_sig_algs.len == 0 || has_name(c.server_sig_algs, SIG_RSA_SHA512) { return SIG_RSA_SHA512; }
    if has_name(c.server_sig_algs, SIG_RSA_SHA256) { return SIG_RSA_SHA256; }
    return SIG_RSA_SHA1;
}

fn auth_header(c: const Conn&, b: u8[>..]&, method: const u8[:]) {
    b.push(MSG_USERAUTH_REQUEST);
    put_string(b, c.user);
    put_string(b, "ssh-connection");
    put_string(b, method);
}

// What a publickey signature covers (RFC 4252 §7).
fn pk_signed_data(session_id: const u8[:], user: const u8[:], alg: const u8[:], blob: const u8[:]) -> u8[>..] {
    var d: u8[>..] = [];
    put_string(d, session_id);
    d.push(MSG_USERAUTH_REQUEST);
    put_string(d, user);
    put_string(d, "ssh-connection");
    put_string(d, "publickey");
    put_bool(d, true);
    put_string(d, alg);
    put_string(d, blob);
    return d;
}

// The next method the server allows that the client has; false for none.
// With no password set for one that takes it, the application is asked.
fn next_auth(c: Conn&, cfg: const ClientConfig&, methods: const u8[:], out: u8[>..]&, events: u8[>..]&) -> bool {
    c.auth_methods.clear();
    c.auth_methods.append(methods[..::min(methods.len, 256)]);
    if has_name(methods, "publickey") && c.key_index < cfg.keys.len {
        let k = cfg.keys[c.key_index];
        var b: u8[>..] = [];
        auth_header(c, b, "publickey");
        put_bool(b, false);
        put_string(b, user_sig_alg(c, k));
        put_string(b, k.public.blob);
        send_packet(c, b, out);
        c.auth_step = AUTH_PK_QUERY;
        return true;
    }
    let takes_password = (has_name(methods, "password") && !c.password_tried) ||
                         (has_name(methods, "keyboard-interactive") && !c.kbd_tried);
    if takes_password && !c.has_password {
        event(events, EV_PASSWORD_NEEDED, 0, 0, "");
        c.auth_step = AUTH_WAIT_PASSWORD;
        return true;
    }
    if has_name(methods, "password") && c.has_password && !c.password_tried {
        var b: u8[>..] = [];
        auth_header(c, b, "password");
        put_bool(b, false);
        put_string(b, c.password);
        send_packet(c, b, out);
        c.password_tried = true;
        c.auth_step = AUTH_PASSWORD;
        return true;
    }
    if has_name(methods, "keyboard-interactive") && c.has_password && !c.kbd_tried {
        var b: u8[>..] = [];
        auth_header(c, b, "keyboard-interactive");
        put_string(b, "");
        put_string(b, "");
        send_packet(c, b, out);
        c.kbd_tried = true;
        c.auth_step = AUTH_KBD;
        return true;
    }
    return false;
}

fn client_auth(c: Conn&, cfg: const ClientConfig&, m: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    let t = m[0];
    var r = rd_at(1, m.len);
    if t == MSG_USERAUTH_BANNER {
        let text = get_string(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad banner", out); }
        event(events, EV_BANNER, 0, 0, bytes(m, text));
        return 0;
    }
    if t == MSG_USERAUTH_SUCCESS {
        c.state = ST_CONNECTED;
        event(events, EV_AUTHENTICATED, 0, 0, c.user);
        return 0;
    }
    if t == MSG_USERAUTH_FAILURE {
        let methods = get_string(r, m);
        let partial = get_bool(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad USERAUTH_FAILURE", out); }
        if c.auth_step == AUTH_PK_QUERY || c.auth_step == AUTH_PK_SIGNED { c.key_index++; }
        if !next_auth(c, cfg, bytes(m, methods), out, events) {
            return fail(c, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "authentication failed", out);
        }
        return 0;
    }
    if t == MSG_USERAUTH_PK_OK && c.auth_step == AUTH_PK_QUERY {
        let alg = get_string(r, m);
        let blob = get_string(r, m);
        let k = cfg.keys[c.key_index];
        if !done(r) || bytes(m, blob) != k.public.blob[..] { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad PK_OK", out); }
        let a = user_sig_alg(c, k);
        var b: u8[>..] = [];
        auth_header(c, b, "publickey");
        put_bool(b, true);
        put_string(b, a);
        put_string(b, k.public.blob);
        let sig, oks = sign(k, a, pk_signed_data(c.session_id, c.user, a, k.public.blob));
        if !oks { return fail(c, DISCONNECT_PROTOCOL_ERROR, "signing failed", out); }
        put_string(b, sig);
        send_packet(c, b, out);
        c.auth_step = AUTH_PK_SIGNED;
        return 0;
    }
    if t == MSG_USERAUTH_INFO_REQUEST && c.auth_step == AUTH_KBD {
        // Each prompt gets the password; none gets an empty response.
        let name = get_string(r, m);
        let instr = get_string(r, m);
        let lang = get_string(r, m);
        let n = get_u32(r, m);
        if r.bad || n > 16 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad INFO_REQUEST", out); }
        for i in n {
            let prompt = get_string(r, m);
            let echo = get_bool(r, m);
        }
        if !done(r) { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad INFO_REQUEST", out); }
        var b: u8[>..] = [];
        b.push(MSG_USERAUTH_INFO_RESPONSE);
        put_u32(b, n);
        for i in n { put_string(b, c.password); }
        send_packet(c, b, out);
        return 0;
    }
    return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected message in authentication", out);
}

// The password asked for by EV_PASSWORD_NEEDED (empty to give up).
fn client_password(c: Conn&, cfg: const ClientConfig&, pw: const u8[:], out: u8[>..]&) -> bool {
    if c.auth_step != AUTH_WAIT_PASSWORD { return false; }
    if pw.len == 0 || pw.len > c.password.cap {
        let r = fail(c, DISCONNECT_AUTH_CANCELLED_BY_USER, "no password", out);
        return false;
    }
    c.password.clear();
    c.password.append(pw);
    c.has_password = true;
    var none: u8[>..] = [];
    var methods: u8[>..] = [];
    methods.append(c.auth_methods);
    if !next_auth(c, cfg, methods, out, none) {
        let r = fail(c, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "authentication failed", out);
        return false;
    }
    return true;
}

// --- Authentication: the server -----------------------------------------------------------

// Whether a key is one of authorized_keys'. A line with options
// (command=, from=, restrict, no-pty, ...) never authorizes: nothing here
// enforces them, and a restriction ignored is a key let in unrestricted.
fn key_authorized(cfg: const ServerConfig&, blob: const u8[:]) -> bool {
    for line in split(cfg.authorized_keys, '\n') {
        let k, opts, comment, ok = parse_authorized_key(line);
        if ok && opts.len == 0 && k.blob[..] == blob { return true; }
    }
    return false;
}

// Whether a user's password is right: "user:password" lines, the password
// plain or a bcrypt hash ($2a$, $2b$, $2y$).
fn password_ok(cfg: const ServerConfig&, user: const u8[:], pw: const u8[:]) -> bool {
    var ok = false;
    for line in split(cfg.passwords, '\n') {
        var colon = 0;
        while colon < line.len && line[colon] != ':' { colon++; }
        if colon == line.len || line[..colon] != user { continue; }
        var secret = line[colon + 1..];
        while secret.len > 0 && (secret[secret.len - 1] == '\r' || secret[secret.len - 1] == ' ') { secret = secret[..secret.len - 1]; }
        if secret.starts_with("$2") { ok = ok || bignum::bcrypt_verify(secret, pw); }
        else { ok = ok || (secret.len == pw.len && bignum::ct_eq_bytes(secret, pw) == 1); }
    }
    return ok;
}

fn user_ok(cfg: const ServerConfig&, user: const u8[:]) -> bool { cfg.auth_user.len == 0 || cfg.auth_user[..] == user }

// The methods a failure names.
fn server_methods(cfg: const ServerConfig&) -> u8[>..] {
    var m: u8[>..] = [];
    if cfg.authorized_keys.len > 0 { add_name(m, "publickey"); }
    if cfg.passwords.len > 0 {
        add_name(m, "password");
        add_name(m, "keyboard-interactive");
    }
    return m;
}

fn auth_failure(c: Conn&, cfg: const ServerConfig&, counts: bool, out: u8[>..]&) -> i64 {
    if counts {
        c.auth_tries++;
        if c.auth_tries >= cfg.max_auth_tries {
            return fail(c, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE, "too many authentication failures", out);
        }
    }
    var b: u8[>..] = [];
    b.push(MSG_USERAUTH_FAILURE);
    put_string(b, server_methods(cfg));
    put_bool(b, false);
    send_packet(c, b, out);
    return 0;
}

fn auth_success(c: Conn&, user: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    let b: u8[1] = [MSG_USERAUTH_SUCCESS];
    send_packet(c, b, out);
    c.user.clear();
    c.user.append(user);
    c.state = ST_CONNECTED;
    event(events, EV_AUTHENTICATED, 0, 0, user);
    return 0;
}

fn server_auth(c: Conn&, cfg: const ServerConfig&, m: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    var r = rd_at(1, m.len);
    if m[0] == MSG_USERAUTH_INFO_RESPONSE && c.kbd_pending {
        c.kbd_pending = false;
        let n = get_u32(r, m);
        var answer = empty_rd();
        if n == 1 { answer = get_string(r, m); }
        if !done(r) || n != 1 { return auth_failure(c, cfg, true, out); }
        let user = c.user[..];
        var u: u8[>..] = [];
        u.append(user);
        if user_ok(cfg, u) && password_ok(cfg, u, bytes(m, answer)) { return auth_success(c, u, out, events); }
        return auth_failure(c, cfg, true, out);
    }
    if m[0] != MSG_USERAUTH_REQUEST { return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected message in authentication", out); }
    let user = get_string(r, m);
    let service = get_string(r, m);
    let method = get_string(r, m);
    if r.bad || user.end - user.pos > 255 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad USERAUTH_REQUEST", out); }
    if bytes(m, service) != "ssh-connection" { return fail(c, DISCONNECT_SERVICE_NOT_AVAILABLE, "unknown service", out); }
    var u: u8[>..] = [];
    u.append(bytes(m, user));
    if cfg.banner.len > 0 && !c.banner_sent {
        var b: u8[>..] = [];
        b.push(MSG_USERAUTH_BANNER);
        put_string(b, cfg.banner);
        put_string(b, "");
        send_packet(c, b, out);
        c.banner_sent = true;
    }
    let meth = bytes(m, method);
    if meth == "none" {
        if cfg.no_client_auth && user_ok(cfg, u) { return auth_success(c, u, out, events); }
        return auth_failure(c, cfg, false, out);
    }
    if meth == "publickey" {
        let has_sig = get_bool(r, m);
        let alg = get_string(r, m);
        let blob = get_string(r, m);
        var sig = empty_rd();
        if has_sig { sig = get_string(r, m); }
        if !done(r) { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad publickey request", out); }
        let k, okk = parse_public_key(bytes(m, blob));
        let a = bytes(m, alg);
        let usable = okk && sig_fits(k.kind, a) && has_name(USER_SIG_ALGS, a) && user_ok(cfg, u) &&
                     key_authorized(cfg, bytes(m, blob));
        if !has_sig {
            if !usable { return auth_failure(c, cfg, false, out); }
            var b: u8[>..] = [];
            b.push(MSG_USERAUTH_PK_OK);
            put_string(b, a);
            put_string(b, bytes(m, blob));
            send_packet(c, b, out);
            return 0;
        }
        if usable && verify(k, a, pk_signed_data(c.session_id, u, a, bytes(m, blob)), bytes(m, sig)) {
            return auth_success(c, u, out, events);
        }
        return auth_failure(c, cfg, true, out);
    }
    if meth == "password" {
        let change = get_bool(r, m);
        let pw = get_string(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad password request", out); }
        if !change && user_ok(cfg, u) && password_ok(cfg, u, bytes(m, pw)) { return auth_success(c, u, out, events); }
        return auth_failure(c, cfg, true, out);
    }
    if meth == "keyboard-interactive" && cfg.passwords.len > 0 {
        // One prompt, the password.
        c.user.clear();
        c.user.append(u);
        c.kbd_pending = true;
        var b: u8[>..] = [];
        b.push(MSG_USERAUTH_INFO_REQUEST);
        put_string(b, "");
        put_string(b, "");
        put_string(b, "");
        put_u32(b, 1);
        put_string(b, "Password: ");
        put_bool(b, false);
        send_packet(c, b, out);
        return 0;
    }
    return auth_failure(c, cfg, false, out);
}

// --- Channels ---------------------------------------------------------------------------

fn channel_ok(c: const Conn&, ch: i64) -> bool { ch >= 0 && ch < c.channels.len && c.channels[ch].state == CH_OPEN }

fn free_slot(c: const Conn&) -> i64 {
    for i in c.channels.len { if c.channels[i].state == CH_FREE { return i; } }
    return -1;
}

// Opens a channel of a type with extra fields (none for a session); its
// number, or -1 when all are in use. EV_CHANNEL_OPENED or
// EV_CHANNEL_OPEN_FAILED follows.
fn open_channel(c: Conn&, kind: const u8[:], extra: const u8[:], out: u8[>..]&) -> i64 {
    if c.state != ST_CONNECTED || c.in_kex { return -1; }
    let i = free_slot(c);
    if i < 0 { return -1; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_OPEN);
    put_string(b, kind);
    put_u32(b, i as! u32);
    put_u32(b, CHANNEL_WINDOW);
    put_u32(b, CHANNEL_MAX_PACKET);
    b.append(extra);
    send_packet(c, b, out);
    c.channels[i] = free_channel();
    c.channels[i].state = CH_OPENING;
    c.channels[i].in_window = CHANNEL_WINDOW;
    return i;
}

fn open_session(c: Conn&, out: u8[>..]&) -> i64 { open_channel(c, "session", "", out) }

// The server takes a channel the peer asked for (EV_CHANNEL_OPEN).
fn channel_accept(c: Conn&, ch: i64, out: u8[>..]&) -> bool {
    if ch < 0 || ch >= c.channels.len || c.channels[ch].state != CH_PEER_OPENING { return false; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_OPEN_CONFIRMATION);
    put_u32(b, c.channels[ch].remote);
    put_u32(b, ch as! u32);
    put_u32(b, CHANNEL_WINDOW);
    put_u32(b, CHANNEL_MAX_PACKET);
    send_packet(c, b, out);
    c.channels[ch].state = CH_OPEN;
    c.channels[ch].in_window = CHANNEL_WINDOW;
    return true;
}

// Reasons for refusing a channel (RFC 4254 §5.1).
let OPEN_ADMINISTRATIVELY_PROHIBITED: u32 = 1;
let OPEN_CONNECT_FAILED: u32 = 2;
let OPEN_UNKNOWN_CHANNEL_TYPE: u32 = 3;
let OPEN_RESOURCE_SHORTAGE: u32 = 4;

fn channel_reject(c: Conn&, ch: i64, reason: u32, msg: const u8[:], out: u8[>..]&) -> bool {
    if ch < 0 || ch >= c.channels.len || c.channels[ch].state != CH_PEER_OPENING { return false; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_OPEN_FAILURE);
    put_u32(b, c.channels[ch].remote);
    put_u32(b, reason);
    put_string(b, msg);
    put_string(b, "");
    send_packet(c, b, out);
    c.channels[ch] = free_channel();
    return true;
}

// Sends data (stderr with ext = 1) as the peer's window and packet size
// allow; how many bytes went (the rest after EV_WINDOW).
fn channel_write(c: Conn&, ch: i64, data: const u8[:], ext: u32, out: u8[>..]&) -> i64 {
    if !channel_ok(c, ch) || c.in_kex || c.channels[ch].sent_eof || c.channels[ch].sent_close { return 0; }
    var off = 0;
    while off < data.len {
        let win: i64 = c.channels[ch].out_window;
        let maxp: i64 = c.channels[ch].out_max;
        let n = ::min(::min(win, maxp), data.len - off);
        if n <= 0 { break; }
        var b: u8[>..] = [];
        b.push(if ext != 0 { MSG_CHANNEL_EXTENDED_DATA } else { MSG_CHANNEL_DATA });
        put_u32(b, c.channels[ch].remote);
        if ext != 0 { put_u32(b, ext); }
        put_string(b, data[off..off + n]);
        send_packet(c, b, out);
        c.channels[ch].out_window -= n as! u32;
        off += n;
    }
    return off;
}

fn channel_send(c: Conn&, ch: i64, data: const u8[:], out: u8[>..]&) -> i64 { channel_write(c, ch, data, 0, out) }
fn channel_send_stderr(c: Conn&, ch: i64, data: const u8[:], out: u8[>..]&) -> i64 { channel_write(c, ch, data, 1, out) }

fn channel_eof(c: Conn&, ch: i64, out: u8[>..]&) {
    if !channel_ok(c, ch) || c.channels[ch].sent_eof || c.channels[ch].sent_close { return; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_EOF);
    put_u32(b, c.channels[ch].remote);
    send_packet(c, b, out);
    c.channels[ch].sent_eof = true;
}

fn channel_close(c: Conn&, ch: i64, out: u8[>..]&) {
    if !channel_ok(c, ch) || c.channels[ch].sent_close { return; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_CLOSE);
    put_u32(b, c.channels[ch].remote);
    send_packet(c, b, out);
    c.channels[ch].sent_close = true;
    if c.channels[ch].recv_close { c.channels[ch] = free_channel(); }
}

// A channel request with its fields; EV_REQUEST_REPLY follows if
// want_reply.
fn channel_request(c: Conn&, ch: i64, kind: const u8[:], want_reply: bool, fields: const u8[:], out: u8[>..]&) -> bool {
    if !channel_ok(c, ch) || c.in_kex || c.channels[ch].sent_close { return false; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_REQUEST);
    put_u32(b, c.channels[ch].remote);
    put_string(b, kind);
    put_bool(b, want_reply);
    b.append(fields);
    send_packet(c, b, out);
    return true;
}

fn exec(c: Conn&, ch: i64, command: const u8[:], out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, command);
    return channel_request(c, ch, "exec", true, f, out);
}

fn shell(c: Conn&, ch: i64, out: u8[>..]&) -> bool { channel_request(c, ch, "shell", true, "", out) }

fn subsystem(c: Conn&, ch: i64, name: const u8[:], out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, name);
    return channel_request(c, ch, "subsystem", true, f, out);
}

fn setenv(c: Conn&, ch: i64, name: const u8[:], value: const u8[:], out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, name);
    put_string(f, value);
    return channel_request(c, ch, "env", true, f, out);
}

// A pseudo-terminal: TERM, the size in characters, no modes.
fn request_pty(c: Conn&, ch: i64, term: const u8[:], cols: u32, rows: u32, out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, term);
    put_u32(f, cols);
    put_u32(f, rows);
    put_u32(f, 0);
    put_u32(f, 0);
    put_string(f, "\x00");        // TTY_OP_END
    return channel_request(c, ch, "pty-req", true, f, out);
}

fn window_change(c: Conn&, ch: i64, cols: u32, rows: u32, out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_u32(f, cols);
    put_u32(f, rows);
    put_u32(f, 0);
    put_u32(f, 0);
    return channel_request(c, ch, "window-change", false, f, out);
}

// The server: a command's exit status, which ends a session.
fn exit_status(c: Conn&, ch: i64, status: u32, out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_u32(f, status);
    return channel_request(c, ch, "exit-status", false, f, out);
}

// The reply to a request the peer wanted one for (EV_REQUEST with value 1),
// in the order they came.
fn channel_reply(c: Conn&, ch: i64, ok: bool, out: u8[>..]&) -> bool {
    if !channel_ok(c, ch) || c.channels[ch].replies == 0 { return false; }
    c.channels[ch].replies--;
    var b: u8[>..] = [];
    b.push(if ok { MSG_CHANNEL_SUCCESS } else { MSG_CHANNEL_FAILURE });
    put_u32(b, c.channels[ch].remote);
    send_packet(c, b, out);
    return true;
}

// Holds a channel's window: the peer may send only as much as the
// application has used (channel_consumed) plus one window, as Go's
// channels open the window as they are read. For an application that
// cannot always take the data at once (a child's stdin), which must still
// read the connection, for the peer's own window adjustments.
fn channel_hold_window(c: Conn&, ch: i64) -> bool {
    if !channel_ok(c, ch) { return false; }
    c.channels[ch].held = true;
    return true;
}

// The application has used n more bytes of a held channel's data.
fn channel_consumed(c: Conn&, ch: i64, n: i64, out: u8[>..]&) {
    if !channel_ok(c, ch) || !c.channels[ch].held || n <= 0 { return; }
    c.channels[ch].consumed += n as! u32;
    open_window(c, ch, out);
}

// A held channel's WINDOW_ADJUST, once half the window is spent and what
// has been used is given back.
fn open_window(c: Conn&, ch: i64, out: u8[>..]&) {
    let k = c.channels[ch];
    if k.in_window >= CHANNEL_WINDOW / 2 || k.consumed == 0 || k.sent_close || c.state != ST_CONNECTED { return; }
    var b: u8[>..] = [];
    b.push(MSG_CHANNEL_WINDOW_ADJUST);
    put_u32(b, k.remote);
    put_u32(b, k.consumed);
    send_packet(c, b, out);
    c.channels[ch].in_window += k.consumed;
    c.channels[ch].consumed = 0;
}

// How many bytes channel_send would take now: the peer's window, at most
// one packet; 0 for a channel that takes none.
fn channel_window(c: const Conn&, ch: i64) -> i64 {
    if !channel_ok(c, ch) || c.in_kex || c.channels[ch].sent_eof || c.channels[ch].sent_close { return 0; }
    let w: i64 = c.channels[ch].out_window;
    let mp: i64 = c.channels[ch].out_max;
    return ::min(w, mp);
}

// --- Global requests and port forwarding ---------------------------------------------

// A global request; EV_GLOBAL_REPLY follows if want_reply (replies come in
// the order the requests went).
fn global_request(c: Conn&, name: const u8[:], want_reply: bool, fields: const u8[:], out: u8[>..]&) -> bool {
    if c.state != ST_CONNECTED || c.in_kex { return false; }
    var b: u8[>..] = [];
    b.push(MSG_GLOBAL_REQUEST);
    put_string(b, name);
    put_bool(b, want_reply);
    b.append(fields);
    send_packet(c, b, out);
    return true;
}

// The server's reply to a global request that wanted one (EV_GLOBAL_REQUEST
// with value 1), in order, with fields for a success.
fn global_reply(c: Conn&, ok: bool, fields: const u8[:], out: u8[>..]&) -> bool {
    if c.global_replies == 0 { return false; }
    c.global_replies--;
    var b: u8[>..] = [];
    b.push(if ok { MSG_REQUEST_SUCCESS } else { MSG_REQUEST_FAILURE });
    if ok { b.append(fields); }
    send_packet(c, b, out);
    return true;
}

// A direct-tcpip channel (-L, -D): the server connects to host:port; the
// originator is where the connection came from.
fn open_direct_tcpip(c: Conn&, host: const u8[:], port: u32, orig_host: const u8[:], orig_port: u32,
                     out: u8[>..]&) -> i64 {
    var f: u8[>..] = [];
    put_string(f, host);
    put_u32(f, port);
    put_string(f, orig_host);
    put_u32(f, orig_port);
    return open_channel(c, "direct-tcpip", f, out);
}

// Asks the server to listen on address:port for the client (-R; port 0:
// any, the reply naming it).
fn tcpip_forward(c: Conn&, address: const u8[:], port: u32, out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, address);
    put_u32(f, port);
    return global_request(c, "tcpip-forward", true, f, out);
}

fn cancel_tcpip_forward(c: Conn&, address: const u8[:], port: u32, out: u8[>..]&) -> bool {
    var f: u8[>..] = [];
    put_string(f, address);
    put_u32(f, port);
    return global_request(c, "cancel-tcpip-forward", true, f, out);
}

// The server's channel for a connection to a forwarded address:port.
fn open_forwarded_tcpip(c: Conn&, address: const u8[:], port: u32, orig_host: const u8[:], orig_port: u32,
                        out: u8[>..]&) -> i64 {
    var f: u8[>..] = [];
    put_string(f, address);
    put_u32(f, port);
    put_string(f, orig_host);
    put_u32(f, orig_port);
    return open_channel(c, "forwarded-tcpip", f, out);
}

// The channel a message names (its first field, our number); -1 for none.
fn channel_of(c: const Conn&, m: const u8[:], r: Rd&) -> i64 {
    let n: i64 = get_u32(r, m);
    if r.bad || n >= c.channels.len || c.channels[n].state == CH_FREE { return -1; }
    return n;
}

fn connection_message(c: Conn&, m: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    let t = m[0];
    var r = rd_at(1, m.len);
    if t == MSG_GLOBAL_REQUEST {
        let name = get_string(r, m);
        let want = get_bool(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad GLOBAL_REQUEST", out); }
        // The server's application answers (tcpip-forward); the client
        // turns down what servers send it (keepalive@openssh.com wanting a
        // reply; hostkeys-00@openssh.com does not), as Go does.
        var d: u8[>..] = [];
        put_string(d, bytes(m, name));
        d.append(m[r.pos..]);
        event(events, EV_GLOBAL_REQUEST, 0, if want { 1 } else { 0 }, d);
        if want && c.is_server {
            c.global_replies++;
        } else if want {
            let b: u8[1] = [MSG_REQUEST_FAILURE];
            send_packet(c, b, out);
        }
        return 0;
    }
    if t == MSG_REQUEST_SUCCESS || t == MSG_REQUEST_FAILURE {
        event(events, EV_GLOBAL_REPLY, 0, if t == MSG_REQUEST_SUCCESS { 1 } else { 0 }, m[1..]);
        return 0;
    }
    if t == MSG_CHANNEL_OPEN {
        let kind = get_string(r, m);
        let sender = get_u32(r, m);
        let window = get_u32(r, m);
        let maxp = get_u32(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad CHANNEL_OPEN", out); }
        let i = free_slot(c);
        if i < 0 || maxp == 0 {
            var b: u8[>..] = [];
            b.push(MSG_CHANNEL_OPEN_FAILURE);
            put_u32(b, sender);
            put_u32(b, OPEN_RESOURCE_SHORTAGE);
            put_string(b, "too many channels");
            put_string(b, "");
            send_packet(c, b, out);
            return 0;
        }
        c.channels[i] = free_channel();
        c.channels[i].state = CH_PEER_OPENING;
        c.channels[i].remote = sender;
        c.channels[i].out_window = window;
        c.channels[i].out_max = maxp;
        var d: u8[>..] = [];
        put_string(d, bytes(m, kind));
        d.append(m[r.pos..]);
        event(events, EV_CHANNEL_OPEN, i, 0, d);
        return 0;
    }
    let ch = channel_of(c, m, r);
    if ch < 0 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "unknown channel", out); }
    if t == MSG_CHANNEL_OPEN_CONFIRMATION {
        let sender = get_u32(r, m);
        let window = get_u32(r, m);
        let maxp = get_u32(r, m);
        if r.bad || c.channels[ch].state != CH_OPENING || maxp == 0 {
            return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad CHANNEL_OPEN_CONFIRMATION", out);
        }
        c.channels[ch].state = CH_OPEN;
        c.channels[ch].remote = sender;
        c.channels[ch].out_window = window;
        c.channels[ch].out_max = maxp;
        event(events, EV_CHANNEL_OPENED, ch, 0, "");
        return 0;
    }
    if t == MSG_CHANNEL_OPEN_FAILURE {
        let reason = get_u32(r, m);
        let desc = get_string(r, m);
        if r.bad || c.channels[ch].state != CH_OPENING { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad CHANNEL_OPEN_FAILURE", out); }
        c.channels[ch] = free_channel();
        event(events, EV_CHANNEL_OPEN_FAILED, ch, reason, bytes(m, desc));
        return 0;
    }
    if c.channels[ch].state != CH_OPEN { return fail(c, DISCONNECT_PROTOCOL_ERROR, "channel not open", out); }
    if t == MSG_CHANNEL_WINDOW_ADJUST {
        let n = get_u32(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad WINDOW_ADJUST", out); }
        let sum: u64 = (c.channels[ch].out_window as u64) + (n as u64);
        c.channels[ch].out_window = if sum > 0xffffffff { 0xffffffff } else { sum as! u32 };
        event(events, EV_WINDOW, ch, n, "");
        return 0;
    }
    if t == MSG_CHANNEL_DATA || t == MSG_CHANNEL_EXTENDED_DATA {
        var code: u32 = 0;
        if t == MSG_CHANNEL_EXTENDED_DATA { code = get_u32(r, m); }
        let d = get_string(r, m);
        let n: i64 = d.end - d.pos;
        let win: i64 = c.channels[ch].in_window;
        if !done(r) || n > win || n > CHANNEL_MAX_PACKET as i64 || c.channels[ch].recv_eof {
            return fail(c, DISCONNECT_PROTOCOL_ERROR, "channel data past the window", out);
        }
        event(events, if t == MSG_CHANNEL_DATA { EV_DATA } else { EV_EXTENDED_DATA }, ch, code, bytes(m, d));
        // The data is the caller's now: the window opens again once half is
        // used (for a held channel, once the caller has used it).
        c.channels[ch].in_window -= n as! u32;
        if c.channels[ch].held {
            open_window(c, ch, out);
        } else if c.channels[ch].in_window < CHANNEL_WINDOW / 2 && !c.channels[ch].sent_close {
            var b: u8[>..] = [];
            b.push(MSG_CHANNEL_WINDOW_ADJUST);
            put_u32(b, c.channels[ch].remote);
            put_u32(b, CHANNEL_WINDOW - c.channels[ch].in_window);
            send_packet(c, b, out);
            c.channels[ch].in_window = CHANNEL_WINDOW;
        }
        return 0;
    }
    if t == MSG_CHANNEL_EOF {
        c.channels[ch].recv_eof = true;
        event(events, EV_EOF, ch, 0, "");
        return 0;
    }
    if t == MSG_CHANNEL_CLOSE {
        c.channels[ch].recv_close = true;
        event(events, EV_CLOSE, ch, 0, "");
        if !c.channels[ch].sent_close {
            var b: u8[>..] = [];
            b.push(MSG_CHANNEL_CLOSE);
            put_u32(b, c.channels[ch].remote);
            send_packet(c, b, out);
        }
        c.channels[ch] = free_channel();
        return 0;
    }
    if t == MSG_CHANNEL_REQUEST {
        let kind = get_string(r, m);
        let want = get_bool(r, m);
        if r.bad { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad CHANNEL_REQUEST", out); }
        let k = bytes(m, kind);
        if k == "exit-status" {
            let status = get_u32(r, m);
            event(events, EV_EXIT_STATUS, ch, status, "");
        } else if k == "exit-signal" {
            let sig = get_string(r, m);
            event(events, EV_EXIT_SIGNAL, ch, 0, if r.bad { "" } else { bytes(m, sig) });
        } else {
            var d: u8[>..] = [];
            put_string(d, k);
            d.append(m[r.pos..]);
            event(events, EV_REQUEST, ch, if want { 1 } else { 0 }, d);
            // The client answers what it does not handle (OpenSSH's
            // keepalive@openssh.com on a channel) at once; the server's
            // application answers with channel_reply.
            if want && !c.is_server {
                var b: u8[>..] = [];
                b.push(MSG_CHANNEL_FAILURE);
                put_u32(b, c.channels[ch].remote);
                send_packet(c, b, out);
            } else if want {
                c.channels[ch].replies++;
            }
        }
        return 0;
    }
    if t == MSG_CHANNEL_SUCCESS || t == MSG_CHANNEL_FAILURE {
        event(events, EV_REQUEST_REPLY, ch, if t == MSG_CHANNEL_SUCCESS { 1 } else { 0 }, "");
        return 0;
    }
    return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected channel message", out);
}

// --- Receiving -----------------------------------------------------------------------------

fn handle_message(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, m: const u8[:], out: u8[>..]&,
                  events: u8[>..]&) -> i64 {
    if m.len == 0 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "empty packet", out); }
    let t = m[0];
    let first_kex = c.kex_count == 0;
    if t == MSG_DISCONNECT {
        var r = rd_at(1, m.len);
        let reason = get_u32(r, m);
        let desc = get_string(r, m);
        c.reason = reason;
        c.state = ST_CLOSED;
        event(events, EV_DISCONNECT, 0, reason, if r.bad { "" } else { bytes(m, desc) });
        return 0;
    }
    // Strict, the first exchange takes nothing but its own messages.
    if first_kex && c.strict && c.peer_kexinit.len > 0 && t != MSG_KEXINIT && t != MSG_NEWKEYS && (t < 30 || t > 49) {
        return fail(c, DISCONNECT_PROTOCOL_ERROR, "strict KEX: unexpected message", out);
    }
    if t == MSG_IGNORE || t == MSG_DEBUG || t == MSG_UNIMPLEMENTED { return 0; }
    if t == MSG_KEXINIT { return on_kexinit(c, ccfg, scfg, m, out); }
    if t >= 30 && t <= 49 {
        if c.ignore_next { c.ignore_next = false; return 0; }
        if !c.in_kex || c.peer_kexinit.len == 0 || c.sent_newkeys {
            return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected KEX message", out);
        }
        if c.is_server && t == MSG_KEX_ECDH_INIT { return server_kex_init(c, scfg, m, out); }
        if !c.is_server && t == MSG_KEX_ECDH_REPLY { return client_kex_reply(c, ccfg, m, out, events); }
        return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected KEX message", out);
    }
    if t == MSG_NEWKEYS { return on_newkeys(c, scfg, m, out); }
    if c.state == ST_KEX || c.state == ST_VERSION {
        return fail(c, DISCONNECT_PROTOCOL_ERROR, "message before the key exchange is done", out);
    }
    // During a rekey, the peer sends nothing but the exchange's messages
    // once it has sent its KEXINIT.
    if c.in_kex && c.peer_kexinit.len > 0 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "message during a rekey", out); }
    if t == MSG_EXT_INFO {
        if c.is_server { return 0; }
        var r = rd_at(1, m.len);
        let n = get_u32(r, m);
        for i in ::min(n as i64, 32) {
            let name = get_string(r, m);
            let value = get_string(r, m);
            if r.bad { break; }
            if bytes(m, name) == "server-sig-algs" && value.end - value.pos <= c.server_sig_algs.cap {
                c.server_sig_algs.clear();
                c.server_sig_algs.append(bytes(m, value));
            }
        }
        return 0;
    }
    if c.state == ST_SERVICE {
        var r = rd_at(1, m.len);
        if c.is_server && t == MSG_SERVICE_REQUEST {
            let name = get_string(r, m);
            if r.bad || bytes(m, name) != "ssh-userauth" { return fail(c, DISCONNECT_SERVICE_NOT_AVAILABLE, "unknown service", out); }
            var b: u8[>..] = [];
            b.push(MSG_SERVICE_ACCEPT);
            put_string(b, "ssh-userauth");
            send_packet(c, b, out);
            c.state = ST_AUTH;
            return 0;
        }
        if !c.is_server && t == MSG_SERVICE_ACCEPT {
            c.state = ST_AUTH;
            var b: u8[>..] = [];
            auth_header(c, b, "none");
            send_packet(c, b, out);
            c.auth_step = AUTH_NONE;
            return 0;
        }
        return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected message before authentication", out);
    }
    if c.state == ST_AUTH {
        if t >= 50 && t <= 79 {
            return if c.is_server { server_auth(c, scfg, m, out, events) } else { client_auth(c, ccfg, m, out, events) };
        }
        return fail(c, DISCONNECT_PROTOCOL_ERROR, "unexpected message during authentication", out);
    }
    if c.state == ST_CONNECTED {
        if t >= 50 && t <= 79 { return 0; }        // after success, authentication requests are ignored (RFC 4252 §5.1)
        if t >= 80 && t <= 127 { return connection_message(c, m, out, events); }
    }
    // Anything else: UNIMPLEMENTED, with its sequence number.
    var b: u8[>..] = [];
    b.push(MSG_UNIMPLEMENTED);
    put_u32(b, c.rx.seq - 1);
    send_packet(c, b, out);
    return 0;
}

// The peer's version line (RFC 4253 §4.2): lines before it are ignored (a
// server may send some); it must be SSH-2.0 (or 1.99) and at most 255 bytes.
fn take_version(c: Conn&, out: u8[>..]&) -> i64 {
    loop {
        var nl = 0;
        while nl < c.inbuf.len && c.inbuf[nl] != '\n' { nl++; }
        if nl == c.inbuf.len {
            if c.inbuf.len > 8192 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "no version line", out); }
            return 0;
        }
        var end = nl;
        if end > 0 && c.inbuf[end - 1] == '\r' { end--; }
        var line: u8[>..] = [];
        line.append(c.inbuf[..end]);
        var rest: u8[>..] = [];
        rest.append(c.inbuf[nl + 1..]);
        c.inbuf.clear();
        c.inbuf.append(rest);
        if line.starts_with("SSH-") {
            if !line.starts_with("SSH-2.0-") && !line.starts_with("SSH-1.99-") {
                return fail(c, DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "not SSH 2", out);
            }
            if line.len > 253 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "version line too long", out); }
            c.peer_version.append(line);
            c.state = ST_KEX;
            return 0;
        }
        if c.is_server { return fail(c, DISCONNECT_PROTOCOL_ERROR, "no version line", out); }
    }
    return 0;
}

// Feeds received bytes; appends what to send to `out` and what happened to
// `events`. Returns 0, or -1 once the connection has failed (c.reason and
// c.message say why).
fn feed(c: Conn&, ccfg: const ClientConfig&, scfg: const ServerConfig&, input: const u8[:], out: u8[>..]&,
        events: u8[>..]&) -> i64 {
    var off = 0;
    while off < input.len || c.inbuf.len > 0 {
        if c.state == ST_FAILED { return -1; }
        if c.state == ST_CLOSED { return 0; }
        let take = ::min(c.inbuf.cap - c.inbuf.len, input.len - off);
        c.inbuf.append(input[off..off + take]);
        off += take;
        var progressed = false;
        if c.state == ST_VERSION {
            if take_version(c, out) != 0 { return -1; }
            if c.state == ST_VERSION { if off < input.len { continue; } else { break; } }
        }
        loop {
            if c.host_key_wait { break; }
            let n = packet_length(c.rx, c.inbuf);
            if n < 0 { return fail(c, DISCONNECT_PROTOCOL_ERROR, "bad packet length", out); }
            if n == 0 || c.inbuf.len < n { break; }
            if c.rx_packets >= MAX_PACKETS { return fail(c, DISCONNECT_PROTOCOL_ERROR, "too many packets under one key", out); }
            let payload, ok = open_packet(c.rx, c.inbuf[..n]);
            if !ok { return fail(c, DISCONNECT_MAC_ERROR, "packet does not authenticate", out); }
            c.rx_bytes += n;
            c.rx_packets++;
            var rest: u8[>..] = [];
            rest.append(c.inbuf[n..]);
            c.inbuf.clear();
            c.inbuf.append(rest);
            progressed = true;
            if handle_message(c, ccfg, scfg, payload, out, events) != 0 { return -1; }
            if c.state == ST_CLOSED { return 0; }
        }
        // Rekey once enough has gone either way, in bytes (rekey_bytes, 0
        // for never) or packets (as Go: counted both ways, sent and
        // received, as RFC 4253 §9 asks). Checked here, as input comes: an
        // application that only sends still gets the peer's window
        // adjustments, so it overshoots by a window at most.
        let limit = if c.is_server { scfg.rekey_bytes } else { ccfg.rekey_bytes };
        let by_bytes = limit > 0 && (c.tx_bytes >= limit || c.rx_bytes >= limit);
        let by_packets = c.tx_packets >= REKEY_PACKETS || c.rx_packets >= REKEY_PACKETS;
        if c.state == ST_CONNECTED && !c.in_kex && (by_bytes || by_packets) {
            let ok = rekey(c, ccfg, scfg, out);
        }
        // Held for the application, or nothing more to do with what came.
        if c.host_key_wait && (take == 0 || off >= input.len) { break; }
        if !progressed && off >= input.len { break; }
    }
    return if c.state == ST_FAILED { -1 } else { 0 };
}

fn no_server() -> ServerConfig {
    var s = server_config();
    s.kex.clear();
    return s;
}

fn no_client() -> ClientConfig { client_config("", "") }

fn client_feed(c: Conn&, cfg: const ClientConfig&, input: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    let none = no_server();
    return feed(c, cfg, none, input, out, events);
}

fn server_feed(c: Conn&, cfg: const ServerConfig&, input: const u8[:], out: u8[>..]&, events: u8[>..]&) -> i64 {
    let none = no_client();
    return feed(c, none, cfg, input, out, events);
}

// Rekeying from the application's side.
fn client_rekey(c: Conn&, cfg: const ClientConfig&, out: u8[>..]&) -> bool {
    let none = no_server();
    return rekey(c, cfg, none, out);
}

fn server_rekey(c: Conn&, cfg: const ServerConfig&, out: u8[>..]&) -> bool {
    let none = no_client();
    return rekey(c, none, cfg, out);
}
