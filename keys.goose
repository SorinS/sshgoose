// ssh.keys: SSH public keys and signatures (RFC 4253 §6.6, RFC 5656,
// RFC 8332, RFC 8709) and the files keys come in: authorized_keys lines,
// OpenSSH's private key format (openssh-key-v1, passphrase-protected or
// not) and the PEM ones x509
// reads (PKCS #8, PKCS #1, SEC 1), with fingerprints. The key types are
// Ed25519, ECDSA on P-256, P-384 and P-521, and RSA, signing as
// rsa-sha2-256, rsa-sha2-512 or (legacy) ssh-rsa; a private key is an
// x509::PrivateKey with its public key beside it.

namespace ssh;

import std;
import base64;
import ssh;
import bignum;
import bignum.ec;
import bignum.ed25519;
import bignum.rsa;
import bignum.hmac;
import bignum.md5;
import bignum.aes;
import bignum.modes;
import bignum.gcm;
import bignum.chacha20;
import bignum.bcrypt;
import bignum.ct;
import bignum.entropy;
import asn1;
import x509;
import x509.keys;

// Signature algorithm names.
let SIG_ED25519: const u8[:] = "ssh-ed25519";
let SIG_ECDSA_P256: const u8[:] = "ecdsa-sha2-nistp256";
let SIG_ECDSA_P384: const u8[:] = "ecdsa-sha2-nistp384";
let SIG_ECDSA_P521: const u8[:] = "ecdsa-sha2-nistp521";
let SIG_RSA_SHA256: const u8[:] = "rsa-sha2-256";
let SIG_RSA_SHA512: const u8[:] = "rsa-sha2-512";
let SIG_RSA_SHA1: const u8[:] = "ssh-rsa";

// A public key: its kind (x509's KEY_* for the types SSH has), its wire
// blob, and its parts: the Ed25519 key or the EC point, or RSA's n and e.
struct PublicKey { kind: i64, point: u8[..133], n: u8[..1024], e: u8[..1024], blob: u8[..2200] }

fn no_public_key() -> PublicKey { PublicKey { kind: x509::KEY_UNKNOWN, point: [], n: [], e: [], blob: [] } }

// A private key, its public key, and a comment.
struct PrivateKey { key: x509::PrivateKey, public: PublicKey, comment: u8[..1024] }

// The key type name of a blob ("ssh-ed25519", "ecdsa-sha2-nistp256",
// "ssh-rsa"), which is also its default signature algorithm.
fn key_type(kind: i64) -> const u8[:] {
    if kind == x509::KEY_ED25519 { return SIG_ED25519; }
    if kind == x509::KEY_EC_P256 { return SIG_ECDSA_P256; }
    if kind == x509::KEY_EC_P384 { return SIG_ECDSA_P384; }
    if kind == x509::KEY_EC_P521 { return SIG_ECDSA_P521; }
    if kind == x509::KEY_RSA { return SIG_RSA_SHA1; }
    return "";
}

// RFC 5656's curve identifier.
fn curve_name(kind: i64) -> const u8[:] {
    if kind == x509::KEY_EC_P256 { "nistp256" } else if kind == x509::KEY_EC_P384 { "nistp384" } else { "nistp521" }
}

fn curve_of(kind: i64) -> bignum::Curve {
    if kind == x509::KEY_EC_P256 { bignum::p256() } else if kind == x509::KEY_EC_P384 { bignum::p384() } else { bignum::p521() }
}

fn is_ecdsa(kind: i64) -> bool { kind == x509::KEY_EC_P256 || kind == x509::KEY_EC_P384 || kind == x509::KEY_EC_P521 }

// The kind a key type name stands for; KEY_UNKNOWN for others.
fn kind_of_type(name: const u8[:]) -> i64 {
    if name == SIG_ED25519 { return x509::KEY_ED25519; }
    if name == SIG_ECDSA_P256 { return x509::KEY_EC_P256; }
    if name == SIG_ECDSA_P384 { return x509::KEY_EC_P384; }
    if name == SIG_ECDSA_P521 { return x509::KEY_EC_P521; }
    if name == SIG_RSA_SHA1 { return x509::KEY_RSA; }
    return x509::KEY_UNKNOWN;
}

// Whether a signature algorithm suits a key kind.
fn sig_fits(kind: i64, alg: const u8[:]) -> bool {
    if kind == x509::KEY_RSA { return alg == SIG_RSA_SHA256 || alg == SIG_RSA_SHA512 || alg == SIG_RSA_SHA1; }
    return kind != x509::KEY_UNKNOWN && alg == key_type(kind);
}

// The kind of key a signature algorithm needs.
fn kind_of_sig(alg: const u8[:]) -> i64 {
    if alg == SIG_RSA_SHA256 || alg == SIG_RSA_SHA512 { return x509::KEY_RSA; }
    return kind_of_type(alg);
}

// --- Numbers --------------------------------------------------------------------

// Little-endian limbs as a minimal big-endian magnitude.
fn limbs_be(limbs: const u32[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = limbs.len;
    while i > 0 {
        i--;
        for j in 4 { out.push((limbs[i] >> (24 - 8 * j)) as! u8); }
    }
    var z = 0;
    while z < out.len && out[z] == 0 { z++; }
    var trimmed: u8[>..] = [];
    trimmed.append(out[z..]);
    return trimmed;
}

// A magnitude left-padded with zeros to n bytes; false if it is longer.
fn pad_be(mag: const u8[:], n: i64) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i < mag.len && mag[i] == 0 { i++; }
    let body = mag[i..];
    if body.len > n { return out, false; }
    out.resize(n - body.len, 0);
    out.append(body);
    return out, true;
}

// --- Public keys ----------------------------------------------------------------

// The blob of a key from its parts.
fn make_blob(k: PublicKey&) {
    var b: u8[>..] = [];
    put_string(b, key_type(k.kind));
    if k.kind == x509::KEY_ED25519 {
        put_string(b, k.point);
    } else if is_ecdsa(k.kind) {
        put_string(b, curve_name(k.kind));
        put_string(b, k.point);
    } else {
        put_mpint(b, k.e);
        put_mpint(b, k.n);
    }
    k.blob.clear();
    k.blob.append(b);
}

// A public key blob (RFC 4253 §6.6): one of the four types, with an EC
// point uncompressed on its curve, and an RSA key of 1024 to 8192 bits
// (Go's lower bound) with an odd exponent.
fn parse_public_key(blob: const u8[:]) -> PublicKey, bool {
    var k = no_public_key();
    if blob.len > k.blob.cap { return k, false; }
    var r = rd(blob);
    let t = get_string(r, blob);
    let kind = kind_of_type(bytes(blob, t));
    if r.bad || kind == x509::KEY_UNKNOWN { return k, false; }
    k.kind = kind;
    if kind == x509::KEY_ED25519 {
        let p = get_string(r, blob);
        if !done(r) || p.end - p.pos != 32 { return k, false; }
        k.point.append(bytes(blob, p));
    } else if is_ecdsa(kind) {
        let cn = get_string(r, blob);
        let p = get_string(r, blob);
        if !done(r) || bytes(blob, cn) != curve_name(kind) { return k, false; }
        let c = curve_of(kind);
        if p.end - p.pos != 2 * c.len + 1 || blob[p.pos] != 4 { return k, false; }
        k.point.append(bytes(blob, p));
        // On the curve: an ECDH with any scalar refuses a point that is not.
        var one: u8[>..] = [];
        one.resize(c.len, 0);
        one[c.len - 1] = 1;
        let s, ok = bignum::ecdh_shared(c, one, k.point);
        if !ok { return k, false; }
    } else {
        let e, oke = get_mpint(r, blob);
        let n, okn = get_mpint(r, blob);
        if !done(r) || !oke || !okn { return k, false; }
        let nb = bytes(blob, n);
        let bits = 8 * nb.len - (if nb.len > 0 { ::clz(nb[0] as u64) - 56 } else { 0 });
        if bits < 1024 || bits > 8192 || nb.len > k.n.cap || e.end - e.pos > k.e.cap { return k, false; }
        k.e.append(bytes(blob, e));
        k.n.append(nb);
        let pub, okp = bignum::rsa_public_from(bignum::from_bytes_be(k.n), bignum::from_bytes_be(k.e));
        if !okp { return k, false; }
    }
    k.blob.append(blob);
    return k, true;
}

// The public key of a private key.
fn public_of(key: const x509::PrivateKey&) -> PublicKey, bool {
    var k = no_public_key();
    k.kind = key.kind;
    if key.kind == x509::KEY_ED25519 {
        k.point.append(bignum::ed25519_public(key.seed));
    } else if is_ecdsa(key.kind) {
        let c = curve_of(key.kind);
        k.point.append(bignum::ec_public_key(c, key.ec_sk));
    } else if key.kind == x509::KEY_RSA {
        k.n.append(limbs_be(key.rsa.n));
        k.e.append(limbs_be(key.rsa.e));
    } else {
        return k, false;
    }
    make_blob(k);
    return k, true;
}

// --- Signatures -----------------------------------------------------------------

fn rsa_hash(alg: const u8[:]) -> i64 {
    if alg == SIG_RSA_SHA512 { 512 } else if alg == SIG_RSA_SHA1 { 160 } else { 256 }
}

// A signature blob over data: string algorithm, string signature, where
// ECDSA's is mpint r, mpint s. Empty and false when RSA's private
// operation fails its check (a fault), as Go's Signer returns an error.
fn sign(k: const PrivateKey&, alg: const u8[:], data: const u8[:]) -> u8[>..], bool {
    assert(sig_fits(k.key.kind, alg));
    var out: u8[>..] = [];
    put_string(out, alg);
    if k.key.kind == x509::KEY_ED25519 {
        put_string(out, bignum::ed25519_sign(k.key.seed, data));
    } else if is_ecdsa(k.key.kind) {
        let c = curve_of(k.key.kind);
        let raw = bignum::ecdsa_sign(c, k.key.ec_sk, data);
        var rs: u8[>..] = [];
        put_mpint(rs, raw[..c.len]);
        put_mpint(rs, raw[c.len..]);
        put_string(out, rs);
    } else {
        let s, ok = bignum::rsa_sign_pkcs1(k.key.rsa, data, rsa_hash(alg));
        if !ok {
            var none: u8[>..] = [];
            return none, false;
        }
        put_string(out, s);
    }
    return out, true;
}

// Whether sig is a signature blob by k over data with algorithm alg
// (which the caller names: the negotiated host key algorithm, or the one
// a userauth request states).
fn verify(k: const PublicKey&, alg: const u8[:], data: const u8[:], sig: const u8[:]) -> bool {
    var r = rd(sig);
    let a = get_string(r, sig);
    let s = get_string(r, sig);
    if !done(r) || bytes(sig, a) != alg || !sig_fits(k.kind, alg) { return false; }
    let raw = bytes(sig, s);
    if k.kind == x509::KEY_ED25519 {
        return raw.len == 64 && bignum::ed25519_verify(k.point, data, raw);
    }
    if is_ecdsa(k.kind) {
        let c = curve_of(k.kind);
        var q = rd(raw);
        let rr, okr = get_mpint(q, raw);
        let ss, oks = get_mpint(q, raw);
        if !done(q) || !okr || !oks { return false; }
        let rp, ok1 = pad_be(bytes(raw, rr), c.len);
        let sp, ok2 = pad_be(bytes(raw, ss), c.len);
        if !ok1 || !ok2 { return false; }
        var rs: u8[>..] = [];
        rs.append(rp);
        rs.append(sp);
        return bignum::ecdsa_verify(c, k.point, data, rs);
    }
    if k.kind == x509::KEY_RSA {
        let pub, okp = bignum::rsa_public_from(bignum::from_bytes_be(k.n), bignum::from_bytes_be(k.e));
        if !okp { return false; }
        // A signature shorter than the modulus is left-padded, as OpenSSH
        // and Go take it.
        let padded, okl = pad_be(raw, bignum::rsa_size(pub));
        return okl && bignum::rsa_verify_pkcs1(pub, data, padded, rsa_hash(alg));
    }
    return false;
}

// --- Text forms -------------------------------------------------------------------

// "type base64 comment" (authorized_keys, .pub files), with a newline.
fn marshal_authorized_key(k: const PublicKey&, comment: const u8[:] = "") -> u8[>..] {
    var out: u8[>..] = [];
    out.append(key_type(k.kind));
    out.push(' ');
    base64::encode(out, k.blob);
    if comment.len > 0 {
        out.push(' ');
        out.append(comment);
    }
    out.push('\n');
    return out;
}

fn is_space(c: u8) -> bool { c == ' ' || c == '\t' }

// One authorized_keys line (sshd(8) AUTHORIZED_KEYS FILE FORMAT): options
// (a comma-separated list, quoted values allowed), the key type, the
// base64 blob and a comment. Returns the key, the options and the comment
// as they are written; false for a blank line, a comment, or one that does
// not hold a key.
fn parse_authorized_key(line: const u8[:]) -> PublicKey, u8[>..], u8[>..], bool {
    var options: u8[>..] = [];
    var comment: u8[>..] = [];
    var i = 0;
    while i < line.len && is_space(line[i]) { i++; }
    if i == line.len || line[i] == '#' || line[i] == '\n' || line[i] == '\r' { return no_public_key(), options, comment, false; }
    // Options come first when the first word is not a key type.
    var j = i;
    while j < line.len && !is_space(line[j]) { j++; }
    if kind_of_type(line[i..j]) == x509::KEY_UNKNOWN {
        var quoted = false;
        j = i;
        while j < line.len && (quoted || !is_space(line[j])) {
            if line[j] == '"' { quoted = !quoted; }
            else if line[j] == '\\' && quoted && j + 1 < line.len { j++; }
            j++;
        }
        if quoted { return no_public_key(), options, comment, false; }
        options.append(line[i..j]);
        i = j;
        while i < line.len && is_space(line[i]) { i++; }
        j = i;
        while j < line.len && !is_space(line[j]) { j++; }
    }
    let kind = kind_of_type(line[i..j]);
    i = j;
    while i < line.len && is_space(line[i]) { i++; }
    j = i;
    while j < line.len && !is_space(line[j]) && line[j] != '\n' && line[j] != '\r' { j++; }
    var blob: u8[>..] = [];
    if kind == x509::KEY_UNKNOWN || !base64::decode(blob, line[i..j]) { return no_public_key(), options, comment, false; }
    let k, ok = parse_public_key(blob);
    if !ok || k.kind != kind { return no_public_key(), options, comment, false; }
    i = j;
    while i < line.len && is_space(line[i]) { i++; }
    var e = line.len;
    while e > i && (line[e - 1] == '\n' || line[e - 1] == '\r' || is_space(line[e - 1])) { e--; }
    comment.append(line[i..e]);
    return k, options, comment, true;
}

// The SHA-256 fingerprint, as ssh-keygen -l shows it: "SHA256:" and the
// base64 of the blob's hash without padding.
fn fingerprint_sha256(k: const PublicKey&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("SHA256:");
    base64::encode(out, bignum::sha256(k.blob));
    while out[out.len - 1] == '=' { out.resize(out.len - 1); }
    return out;
}

// The legacy MD5 fingerprint: the hash's bytes in hex, colon-separated.
fn fingerprint_md5(k: const PublicKey&) -> u8[>..] {
    var out: u8[>..] = [];
    let h = bignum::md5(k.blob);
    for i in 16 {
        if i > 0 { out.push(':'); }
        format_uint(out, h[i], 16, 2, '0');
    }
    return out;
}

// --- Private keys ---------------------------------------------------------------

let OPENSSH_MAGIC: const u8[:] = "openssh-key-v1\x00";

// A private key from its x509 form, with its public key.
fn private_key(key: const x509::PrivateKey&, comment: const u8[:] = "") -> PrivateKey, bool {
    let pub, ok = public_of(key);
    var k = PrivateKey { key: key, public: pub, comment: [] };
    if comment.len <= k.comment.cap { k.comment.append(comment); }
    return k, ok;
}

fn no_private_key() -> PrivateKey {
    let key = x509::empty_key();
    let k, ok = private_key(key);
    return k;
}

// A fresh key of a kind (x509::KEY_ED25519, KEY_EC_P256/384/521, KEY_RSA
// with `bits`).
fn generate_key(kind: i64, bits: i64 = 3072) -> PrivateKey {
    var key = x509::empty_key();
    key.kind = kind;
    if kind == x509::KEY_ED25519 {
        bignum::random_bytes(key.seed);
    } else if is_ecdsa(kind) {
        let c = curve_of(kind);
        var sk: u8[>..] = [];
        sk.resize(c.len, 0);
        loop {
            bignum::random_bytes(sk);
            let s, ok = bignum::ec_scalar(c, sk);
            if ok { break; }
        }
        key.ec_sk.append(sk);
    } else {
        assert(kind == x509::KEY_RSA);
        key.rsa = bignum::rsa_generate(bits);
    }
    let k, ok = private_key(key);
    assert(ok);
    return k;
}

// Errors of parse_private_key.
let KEY_OK: i64 = 0;
let KEY_MALFORMED: i64 = 1;
let KEY_UNSUPPORTED: i64 = 2;           // a key type or cipher this package lacks
let KEY_ENCRYPTED: i64 = 3;             // a passphrase is needed
let KEY_BAD_PASSPHRASE: i64 = 4;

// A private key file: OpenSSH's format ("-----BEGIN OPENSSH PRIVATE
// KEY-----"), with the passphrase if it has one, or PEM PKCS #8 ("PRIVATE
// KEY"), PKCS #1 ("RSA PRIVATE KEY") or SEC 1 ("EC PRIVATE KEY"),
// unencrypted. KEY_OK, or why not: KEY_ENCRYPTED for a protected key and
// no passphrase, KEY_BAD_PASSPHRASE for the wrong one.
fn parse_private_key(text: const u8[:], passphrase: const u8[:] = "") -> PrivateKey, i64 {
    let none = no_private_key();
    let blocks, ok = asn1::pem_decode(text, "OPENSSH PRIVATE KEY");
    if ok && blocks.len == 1 { for blk in blocks { return parse_openssh_key(blk, passphrase); } }
    let labels: const u8[:][3] = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];
    for label in labels {
        let ders, okd = asn1::pem_decode(text, label);
        if okd && ders.len == 1 {
            for der in ders {
                let key, okk = x509::parse_private_key(der);
                if !okk { return none, KEY_MALFORMED; }
                let k, okp = private_key(key);
                return k, if okp { KEY_OK } else { KEY_UNSUPPORTED };
            }
        }
    }
    return none, KEY_MALFORMED;
}

// The ciphers of protected key files, as OpenSSH has them (Go reads the
// AES-256 CTR and CBC ones): aes256-ctr is ssh-keygen's.
let KEY_FILE_CIPHERS: const u8[:] = "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com";
let KEY_FILE_CIPHER: const u8[:] = "aes256-ctr";
let KEY_FILE_ROUNDS: i64 = 16;          // ssh-keygen's bcrypt_pbkdf rounds

// A key file cipher's key, IV and tag lengths and block size.
fn key_file_cipher(name: const u8[:]) -> i64, i64, i64, i64, bool {
    if !has_name(KEY_FILE_CIPHERS, name) { return 0, 0, 0, 0, false; }
    if name == "chacha20-poly1305@openssh.com" { return 64, 0, 16, 8, true; }
    let klen: i64 = if name.starts_with("aes128") { 16 } else if name.starts_with("aes192") { 24 } else { 32 };
    if name.ends_with("-gcm@openssh.com") { return klen, 12, 16, 16, true; }
    return klen, 16, 0, 16, true;
}

// The private section en- or decrypted in place under key || IV (as
// OpenSSH's cipher_crypt with sequence number 0 and no AAD), returning
// the tag, or checking it; false for a tag that does not match.
fn key_file_crypt(name: const u8[:], kiv: const u8[:], data: u8[:], encrypt: bool, tag: u8[16]&) -> bool {
    let klen, ivlen, taglen, bs, ok = key_file_cipher(name);
    assert(ok && kiv.len == klen + ivlen);
    let key = kiv[..klen];
    let iv = kiv[klen..];
    if name == "chacha20-poly1305@openssh.com" {
        let nonce: u8[12] = [0; 12];
        let poly_key = bignum::chacha20_block(key[..32], 0, nonce);
        if !encrypt && bignum::ct_eq_bytes(bignum::poly1305(poly_key[..32], data), tag) == 0 { return false; }
        bignum::chacha20_xor(key[..32], 1, nonce, data);
        if encrypt { tag = bignum::poly1305(poly_key[..32], data); }
        return true;
    }
    if name.ends_with("-gcm@openssh.com") {
        let g = bignum::gcm_init(key);
        if encrypt { tag = bignum::gcm_encrypt(g, iv, "", data); return true; }
        return bignum::gcm_decrypt(g, iv, "", data, tag);
    }
    let a = bignum::aes_init(key);
    if name.ends_with("-ctr") {
        bignum::aes_ctr(a, iv, data);
    } else if encrypt {
        bignum::cbc_encrypt(a, iv, data);
    } else {
        bignum::cbc_decrypt(a, iv, data);
    }
    return true;
}

// The openssh-key-v1 structure (PROTOCOL.key): the cipher, KDF and its
// options, one public key, and the private section (encrypted, a tag
// after it for an AEAD) with its check words, the key and its comment,
// and padding 1, 2, 3, ...
fn parse_openssh_key(b: const u8[:], passphrase: const u8[:]) -> PrivateKey, i64 {
    let none = no_private_key();
    if b.len < OPENSSH_MAGIC.len || b[..OPENSSH_MAGIC.len] != OPENSSH_MAGIC { return none, KEY_MALFORMED; }
    var r = rd_at(OPENSSH_MAGIC.len, b.len);
    let cipher = get_string(r, b);
    let kdf = get_string(r, b);
    let kdf_opts = get_string(r, b);
    let n = get_u32(r, b);
    let pub = get_string(r, b);
    let priv = get_string(r, b);
    if r.bad || n != 1 { return none, KEY_MALFORMED; }
    let cn = bytes(b, cipher);
    if cn == "none" && bytes(b, kdf) == "none" {
        if !done(r) { return none, KEY_MALFORMED; }
        return parse_openssh_private(b, priv, bytes(b, pub));
    }
    let klen, ivlen, taglen, bs, okc = key_file_cipher(cn);
    if bytes(b, kdf) != "bcrypt" || !okc { return none, if cn == "none" || bytes(b, kdf) == "none" { KEY_MALFORMED } else { KEY_UNSUPPORTED }; }
    var o = kdf_opts;
    let salt = get_string(o, b);
    let rounds = get_u32(o, b);
    if !done(o) || salt.pos == salt.end || rounds == 0 || (priv.end - priv.pos) % bs != 0 || r.end - r.pos != taglen {
        return none, KEY_MALFORMED;
    }
    if passphrase.len == 0 { return none, KEY_ENCRYPTED; }
    let kiv, okk = bignum::bcrypt_pbkdf(passphrase, bytes(b, salt), rounds as i64, klen + ivlen);
    if !okk { return none, KEY_MALFORMED; }
    var dec: u8[>..] = [];
    dec.append(bytes(b, priv));
    var tag: u8[16] = [0; 16];
    for i in taglen { tag[i] = b[r.pos + i]; }
    if !key_file_crypt(cn, kiv, dec, false, tag) { return none, KEY_BAD_PASSPHRASE; }
    return parse_openssh_private(dec, rd(dec), bytes(b, pub));
}

fn parse_openssh_private(b: const u8[:], priv: Rd, pub_blob: const u8[:]) -> PrivateKey, i64 {
    let none = no_private_key();
    var p = priv;
    let c1 = get_u32(p, b);
    let c2 = get_u32(p, b);
    if p.bad || c1 != c2 { return none, KEY_BAD_PASSPHRASE; }
    let t = get_string(p, b);
    let kind = kind_of_type(bytes(b, t));
    var key = x509::empty_key();
    key.kind = kind;
    if kind == x509::KEY_ED25519 {
        let pk = get_string(p, b);
        let sk = get_string(p, b);
        if p.bad || pk.end - pk.pos != 32 || sk.end - sk.pos != 64 { return none, KEY_MALFORMED; }
        for i in 32 { key.seed[i] = b[sk.pos + i]; }
    } else if is_ecdsa(kind) {
        let cn = get_string(p, b);
        let q = get_string(p, b);
        let d, okd = get_mpint(p, b);
        let c = curve_of(kind);
        let sk, okp = pad_be(bytes(b, d), c.len);
        if p.bad || !okd || !okp || bytes(b, cn) != curve_name(kind) { return none, KEY_MALFORMED; }
        key.ec_sk.append(sk);
    } else if kind == x509::KEY_RSA {
        let n, ok1 = get_mpint(p, b);
        let e, ok2 = get_mpint(p, b);
        let d, ok3 = get_mpint(p, b);
        let iqmp, ok4 = get_mpint(p, b);
        let pp, ok5 = get_mpint(p, b);
        let qq, ok6 = get_mpint(p, b);
        if p.bad || !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) { return none, KEY_MALFORMED; }
        let rk, okr = bignum::rsa_key_from(bignum::from_bytes_be(bytes(b, n)), bignum::from_bytes_be(bytes(b, e)),
                                           bignum::from_bytes_be(bytes(b, d)), bignum::from_bytes_be(bytes(b, pp)),
                                           bignum::from_bytes_be(bytes(b, qq)));
        if !okr { return none, KEY_MALFORMED; }
        key.rsa = rk;
    } else {
        return none, KEY_UNSUPPORTED;
    }
    let comment = get_string(p, b);
    // The padding: 1, 2, 3, ... to the cipher's block size.
    var i: u8 = 1;
    while p.pos < p.end {
        if get_u8(p, b) != i { return none, KEY_MALFORMED; }
        i++;
    }
    if p.bad { return none, KEY_MALFORMED; }
    let k, okk = private_key(key, bytes(b, comment));
    // The private part must be the key the public part names.
    if !okk || k.public.blob[..] != pub_blob { return none, KEY_MALFORMED; }
    return k, KEY_OK;
}

// A key in OpenSSH's format as ssh-keygen writes it: unencrypted, or with
// a passphrase under a key file cipher and bcrypt_pbkdf with a random
// 16-byte salt and this many rounds.
fn marshal_private_key(k: const PrivateKey&, passphrase: const u8[:] = "", cipher: const u8[:] = KEY_FILE_CIPHER,
                       rounds: i64 = KEY_FILE_ROUNDS) -> u8[>..] {
    let klen, ivlen, taglen, bs0, okc = key_file_cipher(cipher);
    assert(passphrase.len == 0 || (okc && rounds >= 1));
    let bs = if passphrase.len > 0 { bs0 } else { 8 };
    var salt: u8[16] = [0; 16];
    var b: u8[>..] = [];
    b.append(OPENSSH_MAGIC);
    if passphrase.len > 0 {
        bignum::random_bytes(salt);
        put_string(b, cipher);
        put_string(b, "bcrypt");
        let mark = begin_string(b);
        put_string(b, salt);
        put_u32(b, rounds as! u32);
        end_string(b, mark);
    } else {
        put_string(b, "none");
        put_string(b, "none");
        put_string(b, "");
    }
    put_u32(b, 1);
    put_string(b, k.public.blob);
    var p: u8[>..] = [];
    var check: u8[4] = [0; 4];
    bignum::random_bytes(check);
    p.append(check);
    p.append(check);
    put_string(p, key_type(k.key.kind));
    if k.key.kind == x509::KEY_ED25519 {
        put_string(p, k.public.point);
        var sk: u8[>..] = [];
        sk.append(k.key.seed);
        sk.append(k.public.point);
        put_string(p, sk);
    } else if is_ecdsa(k.key.kind) {
        put_string(p, curve_name(k.key.kind));
        put_string(p, k.public.point);
        put_mpint(p, k.key.ec_sk);
    } else {
        put_mpint(p, k.public.n);
        put_mpint(p, k.public.e);
        put_mpint(p, limbs_be(k.key.rsa.d));
        put_mpint(p, limbs_be(k.key.rsa.qinv));
        put_mpint(p, limbs_be(k.key.rsa.p));
        put_mpint(p, limbs_be(k.key.rsa.q));
    }
    put_string(p, k.comment);
    var i: u8 = 1;
    while p.len % bs != 0 { p.push(i); i++; }
    if passphrase.len > 0 {
        let kiv, okk = bignum::bcrypt_pbkdf(passphrase, salt, rounds, klen + ivlen);
        var tag: u8[16] = [0; 16];
        let x = key_file_crypt(cipher, kiv, p, true, tag);
        put_string(b, p);
        b.append(tag[..taglen]);
    } else {
        put_string(b, p);
    }
    var out: u8[>..] = [];
    out.append("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    var text: u8[>..] = [];
    base64::encode(text, b);
    var off = 0;
    while off < text.len {
        let n = ::min(70, text.len - off);
        out.append(text[off..off + n]);
        out.push('\n');
        off += n;
    }
    out.append("-----END OPENSSH PRIVATE KEY-----\n");
    return out;
}
