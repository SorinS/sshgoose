// goose-ssh: an SSH client on this package, as OpenSSH's ssh is used:
//
//   goose-ssh [-p port] [-l user] [-i keyfile]... [-o option=value]... [-t | -T] [-v]
//             [user@]host [command...]
//
// It logs in with the keys given with -i (by default ~/.ssh/id_ed25519,
// id_ecdsa and id_rsa, where they are and are not encrypted) and, when the
// server takes one and no key worked, a password typed at the terminal.
// The host key is checked against ~/.ssh/known_hosts (-o
// UserKnownHostsFile=path); an unknown host is put to the user and added
// once accepted (-o StrictHostKeyChecking=yes refuses it, =accept-new adds
// it without asking, =no takes any key); a changed key always fails.
// -o KexAlgorithms=, Ciphers=, MACs= and HostKeyAlgorithms= set the
// algorithms, comma-separated, as OpenSSH names them. With
// a command it runs that, with stdin, stdout and stderr passed through;
// without one, a shell, on a pseudo-terminal when stdin is a terminal (-t
// forces one, -T refuses one). It exits with the remote exit status, or
// 255 when the connection fails.
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

fn log(s: const u8[:]) { if verbose { sysnet::eprint(str("goose-ssh: ", s, "\n")); } }

fn die(s: const u8[:]) -> i32 {
    sysnet::eprint(str("goose-ssh: ", s, "\n"));
    return 255;
}

fn usage() -> i32 {
    sysnet::eprint("usage: goose-ssh [-p port] [-l user] [-i keyfile]... [-o option=value]... [-t | -T] [-v] [user@]host [command...]\n");
    return 255;
}

// Adds a key file; false if it is not there or not usable (encrypted ones
// are not yet).
fn load_key(cfg: ssh::ClientConfig&, path: const u8[:], required: bool) -> bool {
    var text: u8[>..] = [];
    if !read_file(path, text) {
        if required { sysnet::eprint(str("goose-ssh: cannot read ", path, "\n")); }
        return false;
    }
    let k, e = ssh::parse_private_key(text);
    if e != ssh::KEY_OK {
        let why: const u8[:] = if e == ssh::KEY_ENCRYPTED { "encrypted keys are not supported yet" } else { "not a usable key" };
        sysnet::eprint(str("goose-ssh: ", path, ": ", why, "\n"));
        return false;
    }
    log(str("key ", path, " ", ssh::fingerprint_sha256(k.public)));
    return ssh::add_key(cfg, k);
}

// The connection's state between the socket, the terminal and the Conn.
struct Session {
    sock: i32, ch: i64, exit: i64, opened: bool, done: bool, stdin_eof: bool,
    pty: bool, raw: bool, cols: i32, rows: i32, failed: bool,
    pending: u8[..65536],                  // stdin read but not yet taken by the channel's window
}

fn send_all(sock: i32, out: u8[>..]&) -> bool {
    if out.len == 0 { return true; }
    let n = sysnet::net_write(sock, out);
    out.clear();
    return n >= 0;
}

fn run() -> i32 {
    sysnet::net_init();
    let a = args();
    var port = 22;
    var user: u8[>..] = [];
    var keyfiles: u8[>..] = [];             // one path per line
    var known_hosts_file: u8[>..] = [];
    var strict: u8[>..] = [];
    strict.append("ask");
    var force_pty = 0;                      // 1: -t, -1: -T
    var algs: u8[>..] = [];                 // "kind list" lines from -o
    var target: u8[>..] = [];
    var command: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        if target.len == 0 && w.len > 1 && w[0] == '-' {
            if (w == "-p" || w == "-l" || w == "-i" || w == "-o") && i + 1 >= a.len { return usage(); }
            if w == "-p" {
                let v, ok = parse_int(a[i + 1], 10);
                if !ok || v <= 0 || v > 65535 { return usage(); }
                port = v;
                i += 2;
            } else if w == "-l" {
                user.clear();
                user.append(a[i + 1]);
                i += 2;
            } else if w == "-i" {
                keyfiles.append(a[i + 1]);
                keyfiles.push('\n');
                i += 2;
            } else if w == "-o" {
                let o = a[i + 1];
                if o.starts_with("StrictHostKeyChecking=") { strict.clear(); strict.append(o[22..]); }
                else if o.starts_with("UserKnownHostsFile=") { known_hosts_file.clear(); known_hosts_file.append(o[19..]); }
                else if o.starts_with("Port=") { let v, ok = parse_int(o[5..], 10); if ok { port = v; } }
                else if o.starts_with("User=") { user.clear(); user.append(o[5..]); }
                else if o.starts_with("KexAlgorithms=") { algs.append(str("kex ", o[14..], "\n")); }
                else if o.starts_with("Ciphers=") { algs.append(str("ciphers ", o[8..], "\n")); }
                else if o.starts_with("MACs=") { algs.append(str("macs ", o[5..], "\n")); }
                else if o.starts_with("HostKeyAlgorithms=") { algs.append(str("hostkey ", o[18..], "\n")); }
                else { sysnet::eprint(str("goose-ssh: ignoring option ", o, "\n")); }
                i += 2;
            } else if w == "-t" { force_pty = 1; i++; }
            else if w == "-T" { force_pty = -1; i++; }
            else if w == "-v" { verbose = true; i++; }
            else { return usage(); }
            continue;
        }
        if target.len == 0 { target.append(w); }
        else {
            if command.len > 0 { command.push(' '); }
            command.append(w);
        }
        i++;
    }
    if target.len == 0 { return usage(); }
    // [user@]host[:port]
    var host: u8[>..] = [];
    var at = -1;
    for j in target.len { if target[j] == '@' { at = j; } }
    if at >= 0 {
        if user.len == 0 { user.append(target[..at]); }
        host.append(target[at + 1..]);
    } else {
        host.append(target);
    }
    if user.len == 0 { user = sysnet::user_name(); }
    let home = sysnet::home_dir();
    if known_hosts_file.len == 0 { known_hosts_file.append(str(home, "/.ssh/known_hosts")); }

    var cfg = ssh::client_config(user, host, port);
    var kh: u8[>..] = [];
    let has_kh = read_file(known_hosts_file, kh);
    if has_kh { cfg.known_hosts.append(kh[..::min(kh.len, cfg.known_hosts.cap)]); }
    for line in split(algs, '\n') {
        let w = words(line);
        if w.len != 2 { continue; }
        if w[0] == "kex" { cfg.kex.clear(); cfg.kex.append(w[1]); }
        if w[0] == "ciphers" { cfg.ciphers.clear(); cfg.ciphers.append(w[1]); }
        if w[0] == "macs" { cfg.macs.clear(); cfg.macs.append(w[1]); }
        if w[0] == "hostkey" { cfg.host_key_algs.clear(); cfg.host_key_algs.append(w[1]); }
    }
    if strict == "no" { cfg.host_key_check = ssh::HOST_KEY_INSECURE; }
    else if strict == "yes" { cfg.host_key_check = ssh::HOST_KEY_KNOWN_HOSTS; }
    else { cfg.host_key_check = ssh::HOST_KEY_ASK; }
    if keyfiles.len > 0 {
        for path in split(keyfiles, '\n') { if path.len > 0 { let ok = load_key(cfg, path, true); } }
    } else {
        let defaults: const u8[:][3] = ["/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/id_rsa"];
        for d in defaults {
            let p = str(home, d);
            if file_exists(p) { let ok = load_key(cfg, p, false); }
        }
    }

    log(str("connecting to ", host, " port ", port));
    let sock = sysnet::net_connect(host, port as! i32);
    if sock < 0 { return die(str("cannot connect to ", host, " port ", port)); }
    var c = ssh::client(cfg);
    var out: u8[>..] = [];
    ssh::client_start(c, cfg, out);
    if !send_all(sock, out) { return die("write failed"); }
    let interactive_stdin = sysnet::tty_is(0) == 1;
    var s = Session { sock: sock, ch: -1, exit: -1, opened: false, done: false, stdin_eof: false,
                      pty: force_pty == 1 || (force_pty == 0 && command.len == 0 && interactive_stdin),
                      raw: false, cols: sysnet::tty_cols(0), rows: sysnet::tty_rows(0), failed: false, pending: [] };
    var input: u8[>..] = [];
    while !s.done {
        // Wait for the socket, and for stdin once the session runs.
        let watch_stdin = s.opened && !s.stdin_eof && s.pending.len == 0;
        let ready = sysnet::net_poll(sock, if watch_stdin { 0 } else { -1 }, -1, -1, 500);
        var events: u8[>..] = [];
        if (ready & 1) != 0 {
            input.clear();
            let n = sysnet::read_some(sock, input);
            if n <= 0 {
                if ssh::closed(c) || s.exit >= 0 { break; }
                s.failed = true;
                sysnet::eprint("goose-ssh: connection closed\n");
                break;
            }
            let r = ssh::client_feed(c, cfg, input, out, events);
        }
        if (ready & 2) != 0 {
            var data: u8[>..] = [];
            let n = sysnet::read_some(0, data);
            if n <= 0 {
                s.stdin_eof = true;
                if !s.pty { ssh::channel_eof(c, s.ch, out); }
            } else {
                s.pending.append(data[..::min(data.len, s.pending.cap - s.pending.len)]);
            }
        }
        // The terminal's size, passed on when it changes.
        if s.raw {
            let cols = sysnet::tty_cols(0);
            let rows = sysnet::tty_rows(0);
            if cols != s.cols || rows != s.rows {
                s.cols = cols;
                s.rows = rows;
                let ok = ssh::window_change(c, s.ch, cols as! u32, rows as! u32, out);
            }
        }
        // What happened.
        var pos = 0;
        loop {
            let e, ok = ssh::next_event(events, pos);
            if !ok { break; }
            let d = ssh::bytes(events, e.data);
            if e.kind == ssh::EV_HOST_KEY_UNKNOWN {
                let k, okk = ssh::parse_public_key(d);
                var yes = strict == "accept-new";
                if !yes {
                    sysnet::eprint(str("The authenticity of host '", ssh::known_host_name(cfg), "' can't be established.\n",
                                       ssh::key_type(k.kind), " key fingerprint is ", ssh::fingerprint_sha256(k), ".\n"));
                    let answer = sysnet::ask_line("Are you sure you want to continue connecting (yes/no)? ");
                    yes = answer == "yes";
                }
                if !yes {
                    ssh::disconnect(c, out);
                    let w = send_all(sock, out);
                    return die("host key verification failed");
                }
                let line = ssh::known_hosts_line(cfg, k, false);
                if append_file(known_hosts_file, line) {
                    sysnet::eprint(str("Warning: Permanently added '", ssh::known_host_name(cfg), "' (", ssh::key_type(k.kind),
                                       ") to the list of known hosts.\n"));
                }
                var more: u8[>..] = [];
                let r = ssh::host_key_accept(c, cfg, out, more);
                events.append(more);
            } else if e.kind == ssh::EV_HOST_KEY {
                let k, okk = ssh::parse_public_key(d);
                log(str("host key ", ssh::key_type(k.kind), " ", ssh::fingerprint_sha256(k), "; ", c.kex_name, ", ",
                        c.cipher_c2s, if c.strict { ", strict kex" } else { "" }));
            } else if e.kind == ssh::EV_BANNER {
                sysnet::eprint(d);
            } else if e.kind == ssh::EV_PASSWORD_NEEDED {
                let pw = sysnet::secret(str(user, "@", host, "'s password: "));
                let ok2 = ssh::client_password(c, cfg, pw, out);
            } else if e.kind == ssh::EV_AUTHENTICATED {
                log(str("authenticated as ", user));
                s.ch = ssh::open_session(c, out);
            } else if e.kind == ssh::EV_CHANNEL_OPENED {
                if s.pty {
                    var term: u8[>..] = [];
                    if !env("TERM", term) { term.append("xterm"); }
                    let ok3 = ssh::request_pty(c, s.ch, term, s.cols as! u32, s.rows as! u32, out);
                }
                var lang: u8[>..] = [];
                if env("LANG", lang) { let ok4 = ssh::setenv(c, s.ch, "LANG", lang, out); }
                if command.len > 0 { let ok5 = ssh::exec(c, s.ch, command, out); }
                else { let ok5 = ssh::shell(c, s.ch, out); }
                s.opened = true;
                if s.pty && interactive_stdin { s.raw = sysnet::tty_raw(0) == 0; }
            } else if e.kind == ssh::EV_CHANNEL_OPEN_FAILED {
                sysnet::eprint(str("goose-ssh: channel refused: ", d, "\n"));
                s.done = true;
            } else if e.kind == ssh::EV_DATA {
                write_stdout(d);
                flush_stdout();
            } else if e.kind == ssh::EV_EXTENDED_DATA {
                sysnet::eprint(d);
            } else if e.kind == ssh::EV_EXIT_STATUS {
                s.exit = e.value;
            } else if e.kind == ssh::EV_EXIT_SIGNAL {
                sysnet::eprint(str("goose-ssh: remote command killed by signal ", d, "\n"));
                s.exit = 255;
            } else if e.kind == ssh::EV_CLOSE {
                ssh::disconnect(c, out);
                s.done = true;
            } else if e.kind == ssh::EV_DISCONNECT {
                if !s.done { sysnet::eprint(str("goose-ssh: disconnected: ", d, "\n")); }
                s.done = true;
            }
        }
        // stdin into the channel, as its window allows.
        if s.pending.len > 0 && s.opened && !ssh::closed(c) {
            let n = ssh::channel_send(c, s.ch, s.pending, out);
            var rest: u8[..65536] = [];
            rest.append(s.pending[n..]);
            s.pending = rest;
        }
        if !send_all(sock, out) { s.failed = true; break; }
        if ssh::failed(c) {
            s.failed = true;
            break;
        }
        if ssh::closed(c) { s.done = true; }
    }
    if s.raw { sysnet::tty_restore(0); }
    sysnet::net_close(sock);
    if ssh::failed(c) { return die(str("connection failed: ", c.message)); }
    if s.failed { return 255; }
    return if s.exit >= 0 { s.exit as! i32 } else { 255 };
}

fn main() {
    let code = run();
    flush_stdout();
    exit(code);
}
