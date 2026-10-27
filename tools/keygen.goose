// goose-ssh-keygen: key files as OpenSSH's ssh-keygen makes them:
//
//   goose-ssh-keygen [-t ed25519|ecdsa|rsa] [-b bits] [-C comment] [-N passphrase]
//                    [-Z cipher] [-a rounds] [-f file]
//   goose-ssh-keygen -y [-P passphrase] -f file
//   goose-ssh-keygen -p [-P old] [-N new] [-Z cipher] [-a rounds] -f file
//   goose-ssh-keygen -l [-E sha256|md5] -f file
//
// The first makes a key (Ed25519 by default; ECDSA on P-256, P-384 or
// P-521 by -b; RSA of 3072 bits or -b) and writes it to file
// (~/.ssh/id_<type> by default) in OpenSSH's format, mode 0600, and its
// authorized_keys line to file.pub. With a passphrase (-N, else asked for
// twice at the terminal; empty for none) the key is protected by
// bcrypt_pbkdf with -a rounds (16) under -Z cipher (aes256-ctr, or any of
// ssh.keys' KEY_FILE_CIPHERS). -y prints a private key's public line, -p
// changes its passphrase, -l prints a key's fingerprint as ssh-keygen -l
// does. A passphrase not given is asked for (on the terminal, or from
// $SSH_ASKPASS).
import std;
import os;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;
import .sysnet;

fn usage() -> i32 {
    sysnet::eprint("usage: goose-ssh-keygen [-t ed25519|ecdsa|rsa] [-b bits] [-C comment] [-N passphrase] [-Z cipher] [-a rounds] [-f file]\n");
    sysnet::eprint("       goose-ssh-keygen -y [-P passphrase] -f file\n");
    sysnet::eprint("       goose-ssh-keygen -p [-P old] [-N new] [-Z cipher] [-a rounds] -f file\n");
    sysnet::eprint("       goose-ssh-keygen -l [-E sha256|md5] -f file\n");
    return 1;
}

fn fail(s: const u8[:]) -> i32 {
    sysnet::eprint(str("goose-ssh-keygen: ", s, "\n"));
    return 1;
}

// A private key file, read with the passphrase given or asked for.
fn load(path: const u8[:], given: bool, pass: const u8[:]) -> ssh::PrivateKey, bool {
    var text: u8[>..] = [];
    if !read_file(path, text) {
        let x = fail(str("cannot read ", path));
        return ssh::no_private_key(), false;
    }
    var k, e = ssh::parse_private_key(text, pass);
    if e == ssh::KEY_ENCRYPTED && !given {
        let asked = sysnet::secret("Enter passphrase: ");
        let k2, e2 = ssh::parse_private_key(text, asked);
        k = k2;
        e = e2;
    }
    if e != ssh::KEY_OK {
        let why: const u8[:] = if e == ssh::KEY_BAD_PASSPHRASE || e == ssh::KEY_ENCRYPTED { "incorrect passphrase" }
                               else if e == ssh::KEY_UNSUPPORTED { "unsupported key or cipher" } else { "not a key file" };
        let x = fail(str(path, ": ", why));
        return k, false;
    }
    return k, true;
}

// The new passphrase: -N's, or typed twice.
fn new_passphrase(given: bool, pass: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if given { out.append(pass); return out, true; }
    let a = sysnet::secret("Enter passphrase (empty for no passphrase): ");
    let b = sysnet::secret("Enter same passphrase again: ");
    if a != b { let x = fail("passphrases do not match"); return out, false; }
    out.append(a);
    return out, true;
}

fn save(path: const u8[:], k: const ssh::PrivateKey&, pass: const u8[:], cipher: const u8[:], rounds: i64) -> bool {
    if !write_file(path, ssh::marshal_private_key(k, pass, cipher, rounds)) || sysnet::os_chmod(path, 384) != 0 {  // 0600
        let x = fail(str("cannot write ", path));
        return false;
    }
    return true;
}

fn key_bits(p: const ssh::PublicKey&) -> i64 {
    if p.kind == x509::KEY_ED25519 { return 256; }
    if p.kind == x509::KEY_EC_P256 { return 256; }
    if p.kind == x509::KEY_EC_P384 { return 384; }
    if p.kind == x509::KEY_EC_P521 { return 521; }
    var i = 0;
    while i < p.n.len && p.n[i] == 0 { i++; }
    if i == p.n.len { return 0; }
    return (p.n.len - i) * 8 - clz(p.n[i] as u64) + 56;
}

fn type_label(kind: i64) -> const u8[:] {
    if kind == x509::KEY_ED25519 { return "ED25519"; }
    if kind == x509::KEY_RSA { return "RSA"; }
    return "ECDSA";
}

fn run() -> i32 {
    let a = args();
    var kind: u8[>..] = [];
    kind.append("ed25519");
    var bits: i64 = 0;
    var comment: u8[>..] = [];
    var have_comment = false;
    var newpass: u8[>..] = [];
    var have_new = false;
    var oldpass: u8[>..] = [];
    var have_old = false;
    var cipher: u8[>..] = [];
    cipher.append(ssh::KEY_FILE_CIPHER);
    var rounds = ssh::KEY_FILE_ROUNDS;
    var file: u8[>..] = [];
    var hash: u8[>..] = [];
    hash.append("sha256");
    var mode: u8 = 'g';
    var i = 1;
    while i < a.len {
        let w = a[i];
        if w == "-y" || w == "-p" || w == "-l" { mode = w[1]; i++; continue; }
        if i + 1 >= a.len || w.len != 2 || w[0] != '-' { return usage(); }
        let v = a[i + 1];
        if w == "-t" { kind.clear(); kind.append(v); }
        else if w == "-b" { let n, ok = parse_int(v, 10); if !ok { return usage(); } bits = n; }
        else if w == "-C" { comment.clear(); comment.append(v); have_comment = true; }
        else if w == "-N" { newpass.clear(); newpass.append(v); have_new = true; }
        else if w == "-P" { oldpass.clear(); oldpass.append(v); have_old = true; }
        else if w == "-Z" { cipher.clear(); cipher.append(v); }
        else if w == "-a" { let n, ok = parse_int(v, 10); if !ok || n < 1 { return usage(); } rounds = n; }
        else if w == "-f" { file.clear(); file.append(v); }
        else if w == "-E" { hash.clear(); hash.append(v); }
        else { return usage(); }
        i += 2;
    }
    let kl, il, tl, bs, okc = ssh::key_file_cipher(cipher);
    if !okc { return fail(str("unknown cipher ", cipher)); }
    if mode != 'g' && file.len == 0 { return usage(); }
    if mode == 'y' {
        let k, ok = load(file, have_old, oldpass);
        if !ok { return 1; }
        write_stdout(ssh::marshal_authorized_key(k.public, k.comment));
        return 0;
    }
    if mode == 'l' {
        if hash != "sha256" && hash != "md5" { return usage(); }
        var text: u8[>..] = [];
        if !read_file(file, text) { return fail(str("cannot read ", file)); }
        // A public line (or the .pub beside a private key), else the private key.
        var pub, opts, cmt, okp = ssh::parse_authorized_key(text);
        if !okp {
            var pt: u8[>..] = [];
            if read_file(str(file, ".pub"), pt) {
                let p2, o2, c2, ok2 = ssh::parse_authorized_key(pt);
                pub = p2;
                cmt = copy(c2);
                okp = ok2;
            }
        }
        if !okp {
            let k, ok = load(file, have_old, oldpass);
            if !ok { return 1; }
            pub = k.public;
            cmt.clear();
            cmt.append(k.comment);
        }
        let fp = if hash == "md5" { str("MD5:", ssh::fingerprint_md5(pub)) } else { ssh::fingerprint_sha256(pub) };
        print(key_bits(pub), " ", fp, " ", if cmt.len > 0 { cmt[..] } else { "no comment" }, " (", type_label(pub.kind), ")");
        return 0;
    }
    if mode == 'p' {
        let k, ok = load(file, have_old, oldpass);
        if !ok { return 1; }
        let pass, okn = new_passphrase(have_new, newpass);
        if !okn || !save(file, k, pass, cipher, rounds) { return 1; }
        print("Your identification has been saved with the new passphrase.");
        return 0;
    }
    var xkind: i64 = 0;
    if kind == "ed25519" { xkind = x509::KEY_ED25519; }
    else if kind == "ecdsa" {
        let b = if bits == 0 { 256 } else { bits };
        xkind = if b == 256 { x509::KEY_EC_P256 } else if b == 384 { x509::KEY_EC_P384 } else if b == 521 { x509::KEY_EC_P521 } else { -1 };
        if xkind < 0 { return fail("ECDSA keys are 256, 384 or 521 bits"); }
    } else if kind == "rsa" {
        xkind = x509::KEY_RSA;
        if bits == 0 { bits = 3072; }
        if bits < 1024 || bits > 16384 { return fail("RSA keys are 1024 to 16384 bits"); }
    } else {
        return fail(str("unknown key type ", kind));
    }
    if file.len == 0 { file.append(str(sysnet::home_dir(), "/.ssh/id_", kind)); }
    if file_exists(file) { return fail(str(file, " already exists")); }
    var k = ssh::generate_key(xkind, bits);
    if have_comment { k.comment.append(comment); } else { k.comment.append(str(sysnet::user_name(), "@goose")); }
    let pass, okn = new_passphrase(have_new, newpass);
    if !okn || !save(file, k, pass, cipher, rounds) { return 1; }
    if !write_file(str(file, ".pub"), ssh::marshal_authorized_key(k.public, k.comment)) {
        return fail(str("cannot write ", file, ".pub"));
    }
    print("Your identification has been saved in ", file);
    print("The key fingerprint is: ", ssh::fingerprint_sha256(k.public), " ", k.comment);
    return 0;
}

fn main() { exit(run()); }
