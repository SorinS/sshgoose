// ssh's wire encoding and ssh.keys, against ssh-keygen and Go
// (vectors/keys.txt, scripts/gen_keys.py):
// - mpints, strings and name-lists, and negotiation;
// - every key file parses (OpenSSH's format, PEM PKCS #1, SEC 1, PKCS #8)
//   to the public key of its .pub line, with ssh-keygen's fingerprints;
// - Go's signatures verify, for every algorithm of each key; this
//   package's verify too, and a changed byte, another algorithm or
//   another key does not;
// - authorized_keys lines with options and comments, and keys written in
//   OpenSSH's format read back.
import std;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.keys;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var o: u8[>..] = [];
    for x in b { format_uint(o, x, 16, 2, '0'); }
    return o;
}

// The vector files, by name.
fn key_file(name: const u8[:]) -> const u8[:] {
    if name == "ed25519" { return embed_file("vectors/key_ed25519"); }
    if name == "ecdsa256" { return embed_file("vectors/key_ecdsa256"); }
    if name == "ecdsa384" { return embed_file("vectors/key_ecdsa384"); }
    if name == "ecdsa521" { return embed_file("vectors/key_ecdsa521"); }
    if name == "rsa2048" { return embed_file("vectors/key_rsa2048"); }
    if name == "rsa3072" { return embed_file("vectors/key_rsa3072"); }
    if name == "rsa_pem" { return embed_file("vectors/key_rsa_pem"); }
    if name == "rsa_pkcs8" { return embed_file("vectors/key_rsa_pkcs8"); }
    if name == "ecdsa256_sec1" { return embed_file("vectors/key_ecdsa256_sec1"); }
    if name == "ecdsa384_pkcs8" { return embed_file("vectors/key_ecdsa384_pkcs8"); }
    return embed_file("vectors/key_ed25519_pkcs8");
}

fn pub_file(name: const u8[:]) -> const u8[:] {
    if name == "ed25519" { return embed_file("vectors/key_ed25519.pub"); }
    if name == "ecdsa256" { return embed_file("vectors/key_ecdsa256.pub"); }
    if name == "ecdsa384" { return embed_file("vectors/key_ecdsa384.pub"); }
    if name == "ecdsa521" { return embed_file("vectors/key_ecdsa521.pub"); }
    if name == "rsa2048" { return embed_file("vectors/key_rsa2048.pub"); }
    if name == "rsa3072" { return embed_file("vectors/key_rsa3072.pub"); }
    if name == "rsa_pem" { return embed_file("vectors/key_rsa_pem.pub"); }
    if name == "rsa_pkcs8" { return embed_file("vectors/key_rsa_pkcs8.pub"); }
    if name == "ecdsa256_sec1" { return embed_file("vectors/key_ecdsa256_sec1.pub"); }
    if name == "ecdsa384_pkcs8" { return embed_file("vectors/key_ecdsa384_pkcs8.pub"); }
    return embed_file("vectors/key_ed25519_pkcs8.pub");
}

fn wire() {
    var b: u8[>..] = [];
    ssh::put_mpint(b, unhex("00"));
    ssh::put_mpint(b, unhex("0080"));
    ssh::put_mpint(b, unhex("09a378f9b2e332a7"));
    ssh::put_mpint(b, unhex("7f"));
    // RFC 4251 §5's examples: 0, 0x80 (a zero byte added), 0x9a378f9b2e332a7.
    check("mpints", hex(b) == str("00000000", "000000020080", "0000000809a378f9b2e332a7", "000000017f"));
    var r = ssh::rd(b);
    let z, ok0 = ssh::get_mpint(r, b);
    let x80, ok1 = ssh::get_mpint(r, b);
    let big, ok2 = ssh::get_mpint(r, b);
    let x7f, ok3 = ssh::get_mpint(r, b);
    check("mpints back", ok0 && ok1 && ok2 && ok3 && ssh::done(r) && z.end == z.pos &&
          hex(ssh::bytes(b, x80)) == "80" && hex(ssh::bytes(b, big)) == "09a378f9b2e332a7");
    let neg = unhex("00000001ff");
    var rn = ssh::rd(neg);
    let n1, okn = ssh::get_mpint(rn, neg);
    check("negative mpint", !okn);
    let lead = unhex("000000020001");
    var rl = ssh::rd(lead);
    let l1, okl = ssh::get_mpint(rl, lead);
    check("non-minimal mpint", !okl);
    let short = unhex("00000005abcd");
    var rs = ssh::rd(short);
    let s1 = ssh::get_string(rs, short);
    check("string past the end", rs.bad);
    check("negotiate", ssh::negotiate("a,b,c", "c,b") == "b" && ssh::negotiate("a", "b").len == 0 &&
          ssh::negotiate("curve25519-sha256,ecdh-sha2-nistp256", "ecdh-sha2-nistp256,curve25519-sha256") ==
          "curve25519-sha256");
    check("has_name", ssh::has_name("aa,bb", "bb") && !ssh::has_name("aa,bbb", "bb") && !ssh::has_name("", "a"));
}

fn keys() {
    let data = unhex("7468652064617461207369676e656420666f72207373682e6b65797327207465737473");
    var other = ssh::generate_key(x509::KEY_ED25519);
    for line in split(embed_file("vectors/keys.txt"), '\n') {
        let w = words(line);
        if w.len < 5 { continue; }
        let k, e = ssh::parse_private_key(key_file(w[1]));
        check(str("parse ", w[1]), e == ssh::KEY_OK);
        if e != ssh::KEY_OK { continue; }
        let pub, opts, comment, okp = ssh::parse_authorized_key(pub_file(w[1]));
        check(str("pub line ", w[1]), okp && comment == str("test ", w[1]) && opts.len == 0);
        if w[0] == "key" {
            check(str("public key ", w[1]), k.public.blob[..] == pub.blob[..] && ssh::key_type(k.key.kind) == w[2]);
            check(str("sha256 ", w[1]), ssh::fingerprint_sha256(pub) == w[3]);
            check(str("md5 ", w[1]), ssh::fingerprint_md5(pub) == w[4]);
            // The authorized_keys line, as ssh-keygen wrote it.
            let fields = words(pub_file(w[1]));
            let mine = ssh::marshal_authorized_key(pub, str("test ", w[1]));
            check(str("line ", w[1]), words(mine)[1] == fields[1]);
            // Written in OpenSSH's format, read back.
            let text = ssh::marshal_private_key(k);
            let k2, e2 = ssh::parse_private_key(text);
            check(str("round trip ", w[1]), e2 == ssh::KEY_OK && k2.public.blob[..] == k.public.blob[..] &&
                  k2.comment == k.comment);
            continue;
        }
        // A signature by Go.
        let alg = w[2];
        let sig = unhex(w[4]);
        check(str("go sig ", w[1], " ", alg), ssh::verify(pub, alg, data, sig));
        var bad = copy(sig);
        bad[bad.len - 1] ^= 1;
        check(str("changed sig ", w[1], " ", alg), !ssh::verify(pub, alg, data, bad));
        check(str("other data ", w[1], " ", alg), !ssh::verify(pub, alg, "other", sig));
        check(str("other key ", w[1], " ", alg), !ssh::verify(other.public, alg, data, sig));
        let wrong: const u8[:] = if alg == "rsa-sha2-256" { "rsa-sha2-512" } else { "rsa-sha2-256" };
        check(str("named otherwise ", w[1], " ", alg), !ssh::verify(pub, wrong, data, sig));
        // One of this package's, checked here and by Go (scripts/go_interop.py).
        let mine = ssh::sign(k, alg, data);
        check(str("own sig ", w[1], " ", alg), ssh::verify(pub, alg, data, mine));
        // Ed25519 and RSA PKCS #1 v1.5 are deterministic: the same signature
        // as Go's (whose ECDSA is randomized, unlike RFC 6979's here).
        if !alg.starts_with("ecdsa") { check(str("same as go ", w[1], " ", alg), mine == sig); }
    }
}

fn lines() {
    let pub = embed_file("vectors/key_ed25519.pub");
    let f = words(pub);
    let with_opts = str("command=\"echo \\\"hi there\\\"\",no-pty,from=\"10.0.0.0/8\" ", f[0], " ", f[1], " some comment\n");
    let k, opts, comment, ok = ssh::parse_authorized_key(with_opts);
    check("options", ok && opts == "command=\"echo \\\"hi there\\\"\",no-pty,from=\"10.0.0.0/8\"" && comment == "some comment");
    let k2, o2, c2, ok2 = ssh::parse_authorized_key(str(f[0], " ", f[1]));
    check("no comment", ok2 && c2.len == 0);
    let k3, o3, c3, ok3 = ssh::parse_authorized_key("# a comment line");
    check("comment line", !ok3);
    let k4, o4, c4, ok4 = ssh::parse_authorized_key(str("ssh-rsa ", f[1]));
    check("type mismatch", !ok4);
    let k5, o5, c5, ok5 = ssh::parse_authorized_key(str(f[0], " AAAA!!!"));
    check("bad base64", !ok5);
    let k6, e6 = ssh::parse_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n");
    check("malformed key", e6 == ssh::KEY_MALFORMED);
    // Fresh keys of each kind sign and verify.
    let kinds: i64[5] = [x509::KEY_ED25519, x509::KEY_EC_P256, x509::KEY_EC_P384, x509::KEY_EC_P521, x509::KEY_RSA];
    for kind in kinds {
        let g = ssh::generate_key(kind, 2048);
        let alg: const u8[:] = if kind == x509::KEY_RSA { "rsa-sha2-256" } else { ssh::key_type(kind) };
        let s = ssh::sign(g, alg, "hello");
        let p, okp = ssh::parse_public_key(g.public.blob);
        check(str("generated ", ssh::key_type(kind)), okp && ssh::verify(p, alg, "hello", s));
    }
}

fn main() {
    wire();
    keys();
    lines();
    print("keys: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
