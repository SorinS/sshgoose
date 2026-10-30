// Logging in, for tools/ssh.goose and tools/scp.goose: the options they
// share (-i, -o, -v, -J and the port), the client's configuration from
// them (keys, known_hosts, algorithms), the connection (TCP, or through a
// proxy: -J and ProxyJump as OpenSSH's, goose-ssh -W through each jump
// host, or ProxyCommand), and the events of the login that ask the user
// something (an unknown host key, a password) or tell them (a banner, the
// host key).
namespace login;

import std;
import os;
import ssh.keys;
import ssh.conn;
import .sysnet;

struct Options {
    prog: u8[..32],                 // "goose-ssh", for messages
    port: i64,
    user: u8[..256],
    host: u8[..256],                // as given, for the password prompt
    strict: u8[..16],               // StrictHostKeyChecking: ask, yes, accept-new, no
    verbose: bool,
    jump: u8[..1024],               // -J, ProxyJump: [user@]host[:port] hops, comma-separated
    proxy_command: u8[..4096],      // ProxyCommand, its %h, %p, %r and %% not yet put in
    known_hosts_file: u8[..4096],
    keyfiles: u8[..8192],           // one path per line
    algs: u8[..8192],               // "kind list" lines from -o
}

fn options(prog: const u8[:]) -> Options {
    var o = Options { prog: [], port: 22, user: [], host: [], strict: [], verbose: false, jump: [], proxy_command: [], known_hosts_file: [], keyfiles: [], algs: [] };
    o.prog.append(prog);
    o.strict.append("ask");
    return o;
}

fn log(o: const Options&, s: const u8[:]) { if o.verbose { sysnet::eprint(str(o.prog, ": ", s, "\n")); } }

fn die(o: const Options&, s: const u8[:]) -> i32 {
    sysnet::eprint(str(o.prog, ": ", s, "\n"));
    return 255;
}

// The option at a[i], if it is one of these (port_flag: "-p" for ssh, "-P"
// for scp; -J; -i; -o; -v): 1 when taken (i moved past it), 0 when it is
// not one of them, -1 when it is malformed. The last -J or ProxyJump, and
// the last ProxyCommand, win; "none" turns either off.
fn take_option(o: Options&, a: u8[:][:], i: i64&, port_flag: const u8[:]) -> i64 {
    let w = a[i];
    if w == "-v" { o.verbose = true; i++; return 1; }
    if w != port_flag && w != "-i" && w != "-o" && w != "-J" { return 0; }
    if i + 1 >= a.len { return -1; }
    let v = a[i + 1];
    if w == port_flag {
        let p, ok = parse_int(v, 10);
        if !ok || p <= 0 || p > 65535 { return -1; }
        o.port = p;
    } else if w == "-J" {
        if v.len > o.jump.cap { return -1; }
        o.jump.clear();
        o.jump.append(v);
    } else if w == "-i" {
        if o.keyfiles.len + v.len + 1 > o.keyfiles.cap { return -1; }
        o.keyfiles.append(v);
        o.keyfiles.push('\n');
    } else {
        if v.starts_with("StrictHostKeyChecking=") { o.strict.clear(); o.strict.append(v[22..::min(v.len, 22 + 16)]); }
        else if v.starts_with("UserKnownHostsFile=") {
            if v.len - 19 > o.known_hosts_file.cap { return -1; }
            o.known_hosts_file.clear();
            o.known_hosts_file.append(v[19..]);
        }
        else if v.starts_with("Port=") {
            let p, ok = parse_int(v[5..], 10);
            if !ok || p <= 0 || p > 65535 { return -1; }
            o.port = p;
        }
        else if v.starts_with("ProxyJump=") {
            if v.len - 10 > o.jump.cap { return -1; }
            o.jump.clear();
            o.jump.append(v[10..]);
        }
        else if v.starts_with("ProxyCommand=") {
            if v.len - 13 > o.proxy_command.cap { return -1; }
            o.proxy_command.clear();
            o.proxy_command.append(v[13..]);
        }
        else if v.starts_with("User=") {
            if v.len - 5 > o.user.cap { return -1; }
            o.user.clear();
            o.user.append(v[5..]);
        }
        else if v.starts_with("KexAlgorithms=") || v.starts_with("Ciphers=") || v.starts_with("MACs=") ||
                v.starts_with("HostKeyAlgorithms=") {
            let eq = position(v, '=');
            let kind: const u8[:] = if v[0] == 'K' { "kex" } else if v[0] == 'C' { "ciphers" } else if v[0] == 'M' { "macs" } else { "hostkey" };
            let line = str(kind, " ", v[eq + 1..], "\n");
            if o.algs.len + line.len > o.algs.cap { return -1; }
            o.algs.append(line);
        }
        else { sysnet::eprint(str(o.prog, ": ignoring option ", v, "\n")); }
    }
    i += 2;
    return 1;
}

// [user@]host: the host, the user taken from it unless -l or -o User= named one.
fn split_target(o: Options&, target: const u8[:]) -> u8[>..] {
    var at = -1;
    for j in target.len { if target[j] == '@' { at = j; } }
    var host: u8[>..] = [];
    if at >= 0 {
        if o.user.len == 0 { o.user.append(target[..::min(at, o.user.cap)]); }
        host.append(target[at + 1..]);
    } else {
        host.append(target);
    }
    return host;
}

// Adds a key file; false if it is not there or not usable. For a
// protected one the passphrase is asked for (on the terminal, or from
// $SSH_ASKPASS) up to three times, as ssh does; an empty answer skips it.
fn load_key(o: const Options&, cfg: ssh::ClientConfig&, path: const u8[:], required: bool) -> bool {
    var text: u8[>..] = [];
    if !read_file(path, text) {
        if required { sysnet::eprint(str(o.prog, ": cannot read ", path, "\n")); }
        return false;
    }
    var k, e = ssh::parse_private_key(text);
    var tries = 0;
    while (e == ssh::KEY_ENCRYPTED || e == ssh::KEY_BAD_PASSPHRASE) && tries < 3 {
        if e == ssh::KEY_BAD_PASSPHRASE { sysnet::eprint("Bad passphrase, try again.\n"); }
        let pass = sysnet::secret(str("Enter passphrase for key '", path, "': "));
        if pass.len == 0 { return false; }
        let k2, e2 = ssh::parse_private_key(text, pass);
        k = k2;
        e = e2;
        tries++;
    }
    if e != ssh::KEY_OK {
        let why: const u8[:] = if e == ssh::KEY_BAD_PASSPHRASE { "bad passphrase" }
                               else if e == ssh::KEY_ENCRYPTED { "no passphrase given" } else { "not a usable key" };
        sysnet::eprint(str(o.prog, ": ", path, ": ", why, "\n"));
        return false;
    }
    log(o, str("key ", path, " ", ssh::fingerprint_sha256(k.public)));
    return ssh::add_key(cfg, k);
}

// The client's configuration for host: the user (else the one running
// this), known_hosts (else ~/.ssh/known_hosts), the algorithms from -o,
// the host key policy, and the keys (-i, else ~/.ssh/id_ed25519, id_ecdsa
// and id_rsa where they are).
fn config(o: Options&, host: const u8[:]) -> ssh::ClientConfig {
    if o.user.len == 0 { o.user.append(sysnet::user_name()); }
    o.host.clear();
    o.host.append(host[..::min(host.len, o.host.cap)]);
    let home = sysnet::home_dir();
    if o.known_hosts_file.len == 0 { o.known_hosts_file.append(str(home, "/.ssh/known_hosts")); }
    var cfg = ssh::client_config(o.user, host, o.port);
    var kh: u8[>..] = [];
    if read_file(o.known_hosts_file, kh) { cfg.known_hosts.append(kh[..::min(kh.len, cfg.known_hosts.cap)]); }
    for line in split(o.algs, '\n') {
        let w = words(line);
        if w.len != 2 { continue; }
        if w[0] == "kex" { cfg.kex.clear(); cfg.kex.append(w[1]); }
        if w[0] == "ciphers" { cfg.ciphers.clear(); cfg.ciphers.append(w[1]); }
        if w[0] == "macs" { cfg.macs.clear(); cfg.macs.append(w[1]); }
        if w[0] == "hostkey" { cfg.host_key_algs.clear(); cfg.host_key_algs.append(w[1]); }
    }
    if o.strict == "no" { cfg.host_key_check = ssh::HOST_KEY_INSECURE; }
    else if o.strict == "yes" { cfg.host_key_check = ssh::HOST_KEY_KNOWN_HOSTS; }
    else { cfg.host_key_check = ssh::HOST_KEY_ASK; }
    if o.keyfiles.len > 0 {
        for path in split(o.keyfiles, '\n') { if path.len > 0 { let ok = load_key(o, cfg, path, true); } }
    } else {
        let defaults: const u8[:][3] = ["/.ssh/id_ed25519", "/.ssh/id_ecdsa", "/.ssh/id_rsa"];
        for d in defaults {
            let p = str(home, d);
            if file_exists(p) { let ok = load_key(o, cfg, p, false); }
        }
    }
    return cfg;
}

// The way to the server: a socket (rfd == wfd), or a proxy's pipes, the
// proxy's pid in pid.
struct Transport { rfd: i32, wfd: i32, pid: i32 }

// A host and port as -W and ProxyJump write them: an IPv6 address in
// brackets.
fn host_port(host: const u8[:], port: i64) -> u8[>..] {
    if position(host, ':') >= 0 { return str("[", host, "]:", port); }
    return str(host, ":", port);
}

// A hop of -J, [user@]host[:port]: the user ("" if none), the host, the
// port (0 if none); false if malformed.
fn parse_hop(hop: const u8[:]) -> u8[>..], u8[>..], i64, bool {
    var user: u8[>..] = [];
    var host: u8[>..] = [];
    var rest = hop;
    var at = -1;
    for j in hop.len { if hop[j] == '@' { at = j; } }
    if at >= 0 { user.append(hop[..at]); rest = hop[at + 1..]; }
    var port: i64 = 0;
    var hp = rest;
    if rest.len > 0 && rest[0] == '[' {
        let close = position(rest, ']');
        if close < 0 { return user, host, 0, false; }
        host.append(rest[1..close]);
        hp = rest[close + 1..];
        if hp.len > 0 && hp[0] != ':' { return user, host, 0, false; }
        hp = if hp.len > 0 { hp[1..] } else { hp };
        if hp.len > 0 { let p, ok = parse_int(hp, 10); if !ok || p <= 0 || p > 65535 { return user, host, 0, false; } port = p; }
    } else {
        let colon = position(rest, ':');
        if colon >= 0 {
            host.append(rest[..colon]);
            let p, ok = parse_int(rest[colon + 1..], 10);
            if !ok || p <= 0 || p > 65535 { return user, host, 0, false; }
            port = p;
        } else {
            host.append(rest);
        }
    }
    return user, host, port, host.len > 0;
}

fn add_arg(argv: u8[>..]&, a: const u8[:]) {
    argv.append(a);
    argv.push(0);
}

// Connects to host:port: through ProxyCommand (the user's shell runs it,
// %h, %p, %r and %% put in), else through the last hop of -J (goose-ssh -W
// host:port, from beside this program, the other hops its own -J, with
// this one's keys, known_hosts and host key policy), else over TCP. rfd
// < 0 if it could not.
fn connect(o: const Options&, host: const u8[:], port: i64) -> Transport {
    var none = Transport { rfd: -1, wfd: -1, pid: -1 };
    var argv: u8[>..] = [];
    if o.proxy_command.len > 0 && o.proxy_command != "none" {
        var cmd: u8[>..] = [];
        cmd.append("exec ");
        var i = 0;
        let pc = o.proxy_command;
        while i < pc.len {
            if pc[i] == '%' && i + 1 < pc.len {
                let ch = pc[i + 1];
                if ch == 'h' { cmd.append(host); }
                else if ch == 'p' { format(cmd, port); }
                else if ch == 'r' { cmd.append(o.user); }
                else if ch == '%' { cmd.push('%'); }
                else { cmd.push('%'); cmd.push(ch); }
                i += 2;
                continue;
            }
            cmd.push(pc[i]);
            i++;
        }
        add_arg(argv, "/bin/sh");
        add_arg(argv, "-c");
        add_arg(argv, cmd);
        log(o, str("proxy command: ", cmd));
    } else if o.jump.len > 0 && o.jump != "none" {
        // The last hop is the one that reaches the server; the ones before
        // it are how the proxy reaches that hop.
        var comma = -1;
        for j in o.jump.len { if o.jump[j] == ',' { comma = j; } }
        let hop = o.jump[comma + 1..];
        let hu, hh, hp, ok = parse_hop(hop);
        if !ok { sysnet::eprint(str(o.prog, ": bad jump host ", hop, "\n")); return none; }
        add_arg(argv, str(resource_dir(), "goose-ssh"));
        add_arg(argv, "-W");
        add_arg(argv, host_port(host, port));
        if comma > 0 { add_arg(argv, "-J"); add_arg(argv, o.jump[..comma]); }
        if hp > 0 { add_arg(argv, "-p"); add_arg(argv, str(hp)); }
        if hu.len > 0 { add_arg(argv, "-l"); add_arg(argv, hu); }
        for path in split(o.keyfiles, '\n') { if path.len > 0 { add_arg(argv, "-i"); add_arg(argv, path); } }
        add_arg(argv, "-o");
        add_arg(argv, str("UserKnownHostsFile=", o.known_hosts_file));
        add_arg(argv, "-o");
        add_arg(argv, str("StrictHostKeyChecking=", o.strict));
        if o.verbose { add_arg(argv, "-v"); }
        add_arg(argv, hh);
        log(o, str("jump host ", hop, " to ", host_port(host, port)));
    } else {
        let sock = sysnet::net_connect(host, port as! i32);
        return Transport { rfd: sock, wfd: sock, pid: -1 };
    }
    var to: i32 = -1;
    var from: i32 = -1;
    let pid = sysnet::proc_pipe(argv, to, from);
    if pid < 0 { return none; }
    return Transport { rfd: from, wfd: to, pid: pid };
}

// Closes the way to the server, and waits for a proxy to end.
fn close_transport(t: const Transport&) {
    if t.rfd >= 0 { sysnet::net_close(t.rfd); }
    if t.wfd >= 0 && t.wfd != t.rfd { sysnet::net_close(t.wfd); }
    if t.pid > 0 { let st = sysnet::proc_pipe_end(t.pid); }
}

// The login's events that are the user's business: an unknown host key
// (asked about, or taken with accept-new, and added to known_hosts), the
// host key once checked (logged), a banner (shown), a password wanted
// (asked for). 1: handled; 0: not one of these; -1: the host key was
// refused, the connection ended (its disconnect in out).
fn login_event(o: const Options&, cfg: ssh::ClientConfig&, c: ssh::Conn&, e: ssh::Event, events: u8[>..]&, out: u8[>..]&) -> i64 {
    let d = ssh::bytes(events, e.data);
    if e.kind == ssh::EV_HOST_KEY_UNKNOWN {
        let k, okk = ssh::parse_public_key(d);
        var yes = o.strict == "accept-new";
        if !yes {
            sysnet::eprint(str("The authenticity of host '", ssh::known_host_name(cfg), "' can't be established.\n",
                               ssh::key_type(k.kind), " key fingerprint is ", ssh::fingerprint_sha256(k), ".\n"));
            let answer = sysnet::ask_line("Are you sure you want to continue connecting (yes/no)? ");
            yes = answer == "yes";
        }
        if !yes {
            ssh::disconnect(c, out);
            return -1;
        }
        let line = ssh::known_hosts_line(cfg, k, false);
        if append_file(o.known_hosts_file, line) {
            sysnet::eprint(str("Warning: Permanently added '", ssh::known_host_name(cfg), "' (", ssh::key_type(k.kind),
                               ") to the list of known hosts.\n"));
        }
        var more: u8[>..] = [];
        let r = ssh::host_key_accept(c, cfg, out, more);
        events.append(more);
        return 1;
    }
    if e.kind == ssh::EV_HOST_KEY {
        let k, okk = ssh::parse_public_key(d);
        log(o, str("host key ", ssh::key_type(k.kind), " ", ssh::fingerprint_sha256(k), "; ", c.kex_name, ", ",
                   c.cipher_c2s, if c.strict { ", strict kex" } else { "" }));
        return 1;
    }
    if e.kind == ssh::EV_BANNER {
        sysnet::eprint(d);
        return 1;
    }
    if e.kind == ssh::EV_PASSWORD_NEEDED {
        let pw = sysnet::secret(str(o.user, "@", o.host, "'s password: "));
        let ok = ssh::client_password(c, cfg, pw, out);
        return 1;
    }
    return 0;
}
