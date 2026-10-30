// goose-ssh: an SSH client on this package, as OpenSSH's ssh is used:
//
//   goose-ssh [-p port] [-l user] [-i keyfile]... [-o option=value]... [-t | -T] [-v]
//             [-L [bind:]port:host:hostport]... [-R [bind:]port:host:hostport]...
//             [-D [bind:]port]... [-N] [-W host:port] [-J [user@]host[:port][,...]]
//             [user@]host [command...]
//
// It logs in with the keys given with -i (by default ~/.ssh/id_ed25519,
// id_ecdsa and id_rsa, where they are; for a protected key the passphrase
// is asked for, on the terminal or from $SSH_ASKPASS) and, when the
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
//
// Port forwarding, as OpenSSH's: -L listens here (on localhost unless a
// bind address is given) and has the server connect each connection to
// host:hostport; -R has the server listen (port 0: any, which it names)
// and connects its connections here to host:hostport; -D is a SOCKS5 proxy
// here whose connections the server makes. -N runs no command or shell,
// only the forwards, until the connection ends. -W host:port joins stdin
// and stdout to a connection the server makes to host:port, as OpenSSH's,
// for a proxy: -J [user@]host[:port],... reaches the server through jump
// hosts, each one's connection made by goose-ssh -W through the one
// before (the same keys, known_hosts and host key policy for each); -o
// ProxyJump= is -J, and -o ProxyCommand=command (%h, %p, %r) runs that for
// the connection instead.
import std;
import os;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import ssh.conn;
import .sysnet;
import .relay;
import .login;

fn usage() -> i32 {
    sysnet::eprint("usage: goose-ssh [-p port] [-l user] [-i keyfile]... [-o option=value]... [-t | -T] [-v]\n");
    sysnet::eprint("                 [-L [bind:]port:host:hostport] [-R [bind:]port:host:hostport] [-D [bind:]port] [-N]\n");
    sysnet::eprint("                 [-W host:port] [-J [user@]host[:port][,...]]\n");
    sysnet::eprint("                 [user@]host [command...]\n");
    return 255;
}

// A forward's fields, split at ':' outside [brackets] (for IPv6), the
// brackets dropped.
fn spec_fields(spec: const u8[:]) -> u8[][>..] {
    var out: u8[][>..] = [];
    var cur: u8[>..] = [];
    var depth = 0;
    for ch in spec {
        if ch == '[' { depth++; continue; }
        if ch == ']' { depth--; continue; }
        if ch == ':' && depth == 0 { out.push(copy(cur)); cur.clear(); continue; }
        cur.push(ch);
    }
    out.push(copy(cur));
    return out;
}

// A -L, -R or -D spec as "kind bind port host hostport", or empty.
fn parse_forward(kind: u8, spec: const u8[:]) -> u8[>..] {
    let f = spec_fields(spec);
    var parts: u8[>..] = [];
    var bind: u8[>..] = [];
    var port: u8[>..] = [];
    var host: u8[>..] = [];
    var hostport: u8[>..] = [];
    var n = 0;
    for x in f { n++; }
    var i = 0;
    for x in f {
        let want_bind = (kind == 'D' && n == 2) || (kind != 'D' && n == 4);
        let idx = if want_bind { i } else { i + 1 };
        if idx == 0 { bind.append(x); }
        else if idx == 1 { port.append(x); }
        else if idx == 2 { host.append(x); }
        else if idx == 3 { hostport.append(x); }
        i++;
    }
    let ok_count = if kind == 'D' { n == 1 || n == 2 } else { n == 3 || n == 4 };
    let p, okp = parse_int(port, 10);
    if !ok_count || !okp || p < 0 || p > 65535 { return parts; }
    if kind != 'D' {
        let hp, okh = parse_int(hostport, 10);
        if !okh || hp <= 0 || hp > 65535 || host.len == 0 { return parts; }
    }
    if bind.len == 0 || bind == "localhost" { bind.clear(); bind.append(if kind == 'R' { "localhost" } else { "127.0.0.1" }); }
    if bind == "*" { bind.clear(); bind.append(if kind == 'R' { "" } else { "0.0.0.0" }); }
    parts.push(kind);
    parts.push(' ');
    parts.append(if bind.len > 0 { bind[..] } else { "-" });
    parts.append(str(" ", port, " ", if host.len > 0 { host[..] } else { "-" }, " ", if hostport.len > 0 { hostport[..] } else { "0" }));
    return parts;
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
    var o = login::options("goose-ssh");
    var force_pty = 0;                      // 1: -t, -1: -T
    var forwards: u8[>..] = [];             // "kind bind port host hostport" lines (bind "-" for none)
    var no_command = false;
    var stdio_host: u8[>..] = [];           // -W
    var stdio_port: i64 = 0;
    var target: u8[>..] = [];
    var command: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let w = a[i];
        if target.len == 0 && w.len > 1 && w[0] == '-' {
            let t = login::take_option(o, a, i, "-p");
            if t < 0 { return usage(); }
            if t > 0 { continue; }
            if (w == "-l" || w == "-L" || w == "-R" || w == "-D" || w == "-W") && i + 1 >= a.len { return usage(); }
            if w == "-W" {
                let u, h, p, okw = login::parse_hop(a[i + 1]);
                if !okw || u.len > 0 || p == 0 { sysnet::eprint(str("goose-ssh: bad -W ", a[i + 1], "\n")); return 255; }
                stdio_host.clear();
                stdio_host.append(h);
                stdio_port = p;
                i += 2;
                continue;
            }
            if w == "-L" || w == "-R" || w == "-D" {
                let f = parse_forward(w[1], a[i + 1]);
                if f.len == 0 { sysnet::eprint(str("goose-ssh: bad forward ", w, " ", a[i + 1], "\n")); return 255; }
                forwards.append(f);
                forwards.push('\n');
                i += 2;
                continue;
            }
            if w == "-N" { no_command = true; i++; continue; }
            if w == "-l" {
                if a[i + 1].len > o.user.cap { return usage(); }
                o.user.clear();
                o.user.append(a[i + 1]);
                i += 2;
            } else if w == "-t" { force_pty = 1; i++; }
            else if w == "-T" { force_pty = -1; i++; }
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
    let stdio = stdio_host.len > 0;
    if stdio && (command.len > 0 || no_command) { sysnet::eprint("goose-ssh: -W takes no command and no -N\n"); return 255; }
    // [user@]host
    let host = login::split_target(o, target);
    var cfg = login::config(o, host);
    let port = o.port;
    let verbose = o.verbose;

    login::log(o, str("connecting to ", host, " port ", port));
    let t = login::connect(o, host, port);
    if t.rfd < 0 { return login::die(o, str("cannot connect to ", host, " port ", port)); }
    let sock = t.rfd;
    var c = ssh::client(cfg);
    var out: u8[>..] = [];
    ssh::client_start(c, cfg, out);
    if !send_all(t.wfd, out) { return login::die(o, "write failed"); }
    let interactive_stdin = sysnet::tty_is(0) == 1;
    var s = Session { sock: sock, ch: -1, exit: -1, opened: false, done: false, stdin_eof: false,
                      pty: !stdio && (force_pty == 1 || (force_pty == 0 && command.len == 0 && interactive_stdin)),
                      raw: false, cols: sysnet::tty_cols(0), rows: sysnet::tty_rows(0), failed: false, pending: [] };
    var input: u8[>..] = [];
    var rl = relay::new_relay(verbose);
    // -R forwards: the requests' replies come in order, naming the port for
    // port 0; "port host hostport" lines, the port the server took once known.
    var remote: u8[>..] = [];
    var remote_pending: u8[>..] = [];
    while !s.done {
        // Wait for the socket, stdin once the session runs, and the forwards.
        let watch_stdin = s.opened && !s.stdin_eof && s.pending.len == 0;
        var fds: i32[>..] = [];
        fds.push(sock);
        fds.push(if watch_stdin { 0 } else { -1 });
        relay::poll_fds(rl, c, fds);
        var flags: u8[>..] = [];
        flags.resize(fds.len, 0);
        let nready = sysnet::net_poll_set(fds, flags, 500);
        let ready = (if flags[0] != 0 { 1 } else { 0 }) | (if flags[1] != 0 { 2 } else { 0 });
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
            // A forward's channel.
            if e.channel != s.ch && e.kind != ssh::EV_CHANNEL_OPEN && relay::on_event(rl, c, e, events, out) { continue; }
            if e.kind == ssh::EV_CHANNEL_OPEN {
                // forwarded-tcpip: a connection to a -R port, made here.
                var r = e.data;
                let kind = ssh::get_string(r, events);
                let addr = ssh::get_string(r, events);
                let fport: i64 = ssh::get_u32(r, events);
                var target_host: u8[>..] = [];
                var target_port = 0;
                for line in split(remote, '\n') {
                    let w = words(line);
                    if w.len != 3 { continue; }
                    let bp, okb = parse_int(w[0], 10);
                    if okb && bp == fport { target_host.clear(); target_host.append(w[1]); let tp, okt = parse_int(w[2], 10); target_port = tp; }
                }
                if ssh::bytes(events, kind) == "forwarded-tcpip" && target_host.len > 0 {
                    let x = relay::connect_channel(rl, c, e.channel, target_host, target_port, out);
                } else {
                    let x = ssh::channel_reject(c, e.channel, ssh::OPEN_ADMINISTRATIVELY_PROHIBITED, "not forwarded", out);
                }
                continue;
            }
            if e.kind == ssh::EV_GLOBAL_REPLY {
                // The next -R request's answer.
                var nl = 0;
                while nl < remote_pending.len && remote_pending[nl] != '\n' { nl++; }
                if nl == remote_pending.len { continue; }
                var line: u8[>..] = [];
                line.append(remote_pending[..nl]);
                let w = words(line);
                var rest: u8[>..] = [];
                rest.append(remote_pending[nl + 1..]);
                remote_pending = copy(rest);
                if w.len != 3 { continue; }
                if e.value == 1 {
                    var bound: u8[>..] = [];
                    bound.append(w[0]);
                    if e.data.end - e.data.pos == 4 {
                        var rr = e.data;
                        bound.clear();
                        format_uint(bound, ssh::get_u32(rr, events), 10, 0, ' ');
                        sysnet::eprint(str("Allocated port ", bound, " for remote forward to ", w[1], ":", w[2], "\n"));
                    }
                    remote.append(str(bound, " ", w[1], " ", w[2], "\n"));
                    login::log(o, str("remote forward on port ", bound, " to ", w[1], ":", w[2]));
                } else {
                    sysnet::eprint(str("Warning: remote port forwarding failed for listen port ", w[0], "\n"));
                }
                continue;
            }
            let le = login::login_event(o, cfg, c, e, events, out);
            if le < 0 {
                let w = send_all(t.wfd, out);
                return login::die(o, "host key verification failed");
            }
            if le > 0 {
                continue;
            } else if e.kind == ssh::EV_AUTHENTICATED {
                login::log(o, str("authenticated as ", o.user));
                for line in split(forwards, '\n') {
                    let w = words(line);
                    if w.len != 5 { continue; }
                    let bind: const u8[:] = if w[1] == "-" { "" } else { w[1] };
                    let fp, okp = parse_int(w[2], 10);
                    let hp, okh = parse_int(w[4], 10);
                    if w[0] == "R" {
                        let ok6 = ssh::tcpip_forward(c, bind, fp as! u32, out);
                        remote_pending.append(str(fp, " ", w[3], " ", hp, "\n"));
                        continue;
                    }
                    let kind = if w[0] == "L" { relay::FWD_LOCAL } else { relay::FWD_DYNAMIC };
                    if relay::listen(rl, kind, bind, fp, w[3], hp) {
                        let what: u8[>..] = if w[0] == "L" { str(" for ", w[3], ":", hp) } else { " (SOCKS)" };
                        login::log(o, str("listening on ", bind, ":", fp, what));
                    } else {
                        sysnet::eprint(str("goose-ssh: cannot listen on ", bind, " port ", fp, "\n"));
                    }
                }
                if stdio { s.ch = ssh::open_direct_tcpip(c, stdio_host, stdio_port as! u32, "127.0.0.1", 65535, out); }
                else if !no_command { s.ch = ssh::open_session(c, out); }
            } else if e.kind == ssh::EV_CHANNEL_OPENED && stdio {
                login::log(o, str("connected to ", login::host_port(stdio_host, stdio_port)));
                s.opened = true;
            } else if e.kind == ssh::EV_EOF && stdio && e.channel == s.ch {
                // The far end is done sending: so is our stdout, which a
                // proxy's reader sees as the end.
                flush_stdout();
                sysnet::net_close(1);
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
                if stdio { sysnet::eprint(str("goose-ssh: -W ", login::host_port(stdio_host, stdio_port), ": ", d, "\n")); }
                else { sysnet::eprint(str("goose-ssh: channel refused: ", d, "\n")); }
                s.failed = stdio;
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
        // The forwards' sockets.
        relay::service(rl, c, fds, flags, 2, out);
        // stdin into the channel, as its window allows.
        if s.pending.len > 0 && s.opened && !ssh::closed(c) {
            let n = ssh::channel_send(c, s.ch, s.pending, out);
            var rest: u8[..65536] = [];
            rest.append(s.pending[n..]);
            s.pending = rest;
        }
        if !send_all(t.wfd, out) { s.failed = true; break; }
        if ssh::failed(c) {
            s.failed = true;
            break;
        }
        if ssh::closed(c) { s.done = true; }
    }
    if s.raw { sysnet::tty_restore(0); }
    login::close_transport(t);
    if ssh::failed(c) { return login::die(o, str("connection failed: ", c.message)); }
    if s.failed { return 255; }
    if stdio { return if s.opened { 0 } else { 255 }; }
    return if s.exit >= 0 { s.exit as! i32 } else { 255 };
}

fn main() {
    let code = run();
    flush_stdout();
    exit(code);
}
