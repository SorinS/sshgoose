// ssh.kex: the key exchanges (RFC 4253 §7-8), with the exchange hash and
// the keys derived from it: mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-
// hybrid-kex), curve25519-sha256 (RFC 8731, also as
// curve25519-sha256@libssh.org), ecdh-sha2-nistp256/384/521 (RFC 5656),
// and diffie-hellman-group14-sha256, group16-sha512 and (legacy)
// group14-sha1 (RFC 8268, over bignum.ffdh). All but Diffie-Hellman
// exchange strings; DH exchanges mpints.

namespace ssh;

import std;
import ssh;
import bignum;
import bignum.x25519;
import bignum.ec;
import bignum.mlkem;
import bignum.hmac;
import bignum.ffdh;
import bignum.entropy;
import x509;
import keys;

// Go's default key exchanges, in its order, and all this package takes.
let KEX_DEFAULT: const u8[:] = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";
let KEX_SUPPORTED: const u8[:] = "mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha1";


let KEX_MLKEM768X25519: i64 = 1;
let KEX_CURVE25519: i64 = 2;
let KEX_ECDH: i64 = 3;
let KEX_DH: i64 = 4;

// A key exchange in progress: the method and its hash, this side's secret
// (X25519's, the EC scalar, ML-KEM's seed, DH's exponent) and public value
// as it goes on the wire (a string's contents, or DH's magnitude).
struct Kex {
    method: i64, name: u8[..64], hash: i64, curve_kind: i64,
    x25519_sk: u8[32], ec_sk: u8[..66], mlkem_seed: u8[64], dh_x: u8[..128], dh_p: u8[..512],
    mine: u8[..1300],
}


// The method a name stands for, and its hash; false for one this package
// lacks.
fn kex_method(name: const u8[:]) -> Kex, bool {
    var k = Kex { method: 0, name: [], hash: 256, curve_kind: 0, x25519_sk: [0; 32], ec_sk: [], mlkem_seed: [0; 64],
                  dh_x: [], dh_p: [], mine: [] };
    if name.len > k.name.cap { return k, false; }
    k.name.append(name);
    if name == "mlkem768x25519-sha256" { k.method = KEX_MLKEM768X25519; return k, true; }
    if name == "curve25519-sha256" || name == "curve25519-sha256@libssh.org" { k.method = KEX_CURVE25519; return k, true; }
    if name == "ecdh-sha2-nistp256" { k.method = KEX_ECDH; k.curve_kind = x509::KEY_EC_P256; return k, true; }
    if name == "ecdh-sha2-nistp384" { k.method = KEX_ECDH; k.curve_kind = x509::KEY_EC_P384; k.hash = 384; return k, true; }
    if name == "ecdh-sha2-nistp521" { k.method = KEX_ECDH; k.curve_kind = x509::KEY_EC_P521; k.hash = 512; return k, true; }
    if name == "diffie-hellman-group14-sha256" || name == "diffie-hellman-group14-sha1" {
        k.method = KEX_DH;
        k.hash = if name.ends_with("sha1") { 160 } else { 256 };
        k.dh_p.append(bignum::ffdh_prime(14));
        return k, true;
    }
    if name == "diffie-hellman-group16-sha512" {
        k.method = KEX_DH;
        k.hash = 512;
        k.dh_p.append(bignum::ffdh_prime(16));
        return k, true;
    }
    return k, false;
}

// --- Both sides -------------------------------------------------------------------

// This side's ephemeral key: a fresh secret and its public value (k.mine).
// The client's for every method; the server's for the ECDH and DH ones,
// before it answers (ML-KEM's server side encapsulates instead).
fn kex_keygen(k: Kex&) {
    k.mine.clear();
    if k.method == KEX_CURVE25519 || k.method == KEX_MLKEM768X25519 {
        bignum::random_bytes(k.x25519_sk);
        let pk = bignum::x25519_base(k.x25519_sk);
        if k.method == KEX_MLKEM768X25519 {
            bignum::random_bytes(k.mlkem_seed);
            let ek, dk = bignum::mlkem_keys_from_seed(3, k.mlkem_seed);
            k.mine.append(ek);
        }
        k.mine.append(pk);
    } else if k.method == KEX_ECDH {
        let c = curve_of(k.curve_kind);
        var sk: u8[>..] = [];
        sk.resize(c.len, 0);
        loop {
            bignum::random_bytes(sk);
            let s, ok = bignum::ec_scalar(c, sk);
            if ok { break; }
        }
        k.ec_sk.clear();
        k.ec_sk.append(sk);
        k.mine.append(bignum::ec_public_key(c, sk));
    } else {
        // An exponent of twice the hash's strength, as OpenSSH draws it.
        let x, e = bignum::ffdh_keygen(k.dh_p, if k.hash == 512 { 128 } else { 64 });
        k.dh_x.clear();
        k.dh_x.append(x);
        k.mine.append(e);
    }
}

// The client's shared secret K, encoded as the hash and derivation take
// it (an mpint, or for the hybrid a string), from the server's public
// value; false for one that is not valid.
fn kex_client_secret(k: const Kex&, theirs: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if k.method == KEX_MLKEM768X25519 {
        if theirs.len != 1088 + 32 { return out, false; }
        let s1, ok1 = bignum::mlkem_decaps(3, k.mlkem_seed, theirs[..1088]);
        let s2, ok2 = bignum::x25519_shared(k.x25519_sk, theirs[1088..]);
        if !ok1 || !ok2 { return out, false; }
        var both: u8[>..] = [];
        both.append(s1);
        both.append(s2);
        put_string(out, bignum::sha256(both));
        return out, true;
    }
    return shared_secret(k, theirs);
}

// The ECDH or DH secret with the peer's public value, as an mpint.
fn shared_secret(k: const Kex&, theirs: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if k.method == KEX_CURVE25519 {
        if theirs.len != 32 { return out, false; }
        let s, ok = bignum::x25519_shared(k.x25519_sk, theirs);
        if !ok { return out, false; }
        put_mpint(out, s);
        return out, true;
    }
    if k.method == KEX_ECDH {
        let c = curve_of(k.curve_kind);
        if theirs.len != 2 * c.len + 1 { return out, false; }
        let s, ok = bignum::ecdh_shared(c, k.ec_sk, theirs);
        if !ok { return out, false; }
        put_mpint(out, s);
        return out, true;
    }
    let s, ok = bignum::ffdh_shared(k.dh_x, theirs, k.dh_p);
    if !ok { return out, false; }
    put_mpint(out, s);
    return out, true;
}

// The server's side: its public value (k.mine) and K from the client's.
// For the hybrid it encapsulates to the client's ML-KEM key.
fn kex_server_secret(k: Kex&, theirs: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if k.method == KEX_MLKEM768X25519 {
        if theirs.len != 1184 + 32 { return out, false; }
        var m: u8[32] = [0; 32];
        bignum::random_bytes(m);
        let s1, ct, ok1 = bignum::mlkem_encaps_with(3, theirs[..1184], m);
        bignum::random_bytes(k.x25519_sk);
        let pk = bignum::x25519_base(k.x25519_sk);
        let s2, ok2 = bignum::x25519_shared(k.x25519_sk, theirs[1184..]);
        if !ok1 || !ok2 { return out, false; }
        k.mine.clear();
        k.mine.append(ct);
        k.mine.append(pk);
        var both: u8[>..] = [];
        both.append(s1);
        both.append(s2);
        put_string(out, bignum::sha256(both));
        return out, true;
    }
    kex_keygen(k);
    return shared_secret(k, theirs);
}

// How a public value goes into the exchange hash and the messages: an
// mpint for DH, a string otherwise.
fn put_kex_value(out: u8[>..]&, k: const Kex&, v: const u8[:]) {
    if k.method == KEX_DH { put_mpint(out, v); } else { put_string(out, v); }
}

// The exchange hash H: the hash of both versions and KEXINIT payloads, the
// host key, both public values and K (RFC 4253 §8, RFC 5656 §4).
fn exchange_hash(k: const Kex&, v_c: const u8[:], v_s: const u8[:], i_c: const u8[:], i_s: const u8[:],
                 host_key: const u8[:], q_c: const u8[:], q_s: const u8[:], k_enc: const u8[:]) -> u8[>..] {
    var b: u8[>..] = [];
    put_string(b, v_c);
    put_string(b, v_s);
    put_string(b, i_c);
    put_string(b, i_s);
    put_string(b, host_key);
    put_kex_value(b, k, q_c);
    put_kex_value(b, k, q_s);
    b.append(k_enc);
    return bignum::hash_bits(k.hash, b);
}

// A derived key (RFC 4253 §7.2): HASH(K || H || letter || session_id),
// extended with HASH(K || H || what came before) to n bytes.
fn derive_key(hash: i64, k_enc: const u8[:], h: const u8[:], letter: u8, session_id: const u8[:], n: i64) -> u8[>..] {
    var b: u8[>..] = [];
    b.append(k_enc);
    b.append(h);
    b.push(letter);
    b.append(session_id);
    var out = bignum::hash_bits(hash, b);
    while out.len < n {
        var more: u8[>..] = [];
        more.append(k_enc);
        more.append(h);
        more.append(out);
        out.append(bignum::hash_bits(hash, more));
    }
    out.resize(n);
    return out;
}
