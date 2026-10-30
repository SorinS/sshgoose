// Logging in, for tools/ssh.goose and tools/scp.goose: the options they
// share (-i, -o, -v and the port), the client's configuration from them
// (keys, known_hosts, algorithms), and the events of the login that ask
// the user something (an unknown host key, a password) or tell them (a
// banner, the host key).
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
    known_hosts_file: u8[..4096],
    keyfiles: u8[..8192],           // one path per line
    algs: u8[..8192],               // "kind list" lines from -o
}

fn options(prog: const u8[:]) -> Options {
    var o = Options { prog: [], port: 22, user: [], host: [], strict: [], verbose: false, known_hosts_file: [], keyfiles: [], algs: [] };
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
// for scp): 1 when taken (i moved past it), 0 when it is not one of them,
// -1 when it is malformed.
fn take_option(o: Options&, a: u8[:][:], i: i64&, port_flag: const u8[:]) -> i64 {
    let w = a[i];
    if w == "-v" { o.verbose = true; i++; return 1; }
    if w != port_flag && w != "-i" && w != "-o" { return 0; }
    if i + 1 >= a.len { return -1; }
    let v = a[i + 1];
    if w == port_flag {
        let p, ok = parse_int(v, 10);
        if !ok || p <= 0 || p > 65535 { return -1; }
        o.port = p;
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
