// ssh.cipher: the binary packet protocol (RFC 4253 §6) and its
// protection, one direction at a time: chacha20-poly1305@openssh.com
// (PROTOCOL.chacha20poly1305), aes128-gcm@openssh.com and
// aes256-gcm@openssh.com (RFC 5647 as OpenSSH has it), and AES-CTR
// (RFC 4344) with hmac-sha2-256, hmac-sha2-512 or hmac-sha1, MAC then
// encrypt, or their -etm@openssh.com forms, encrypt then MAC; and "none",
// before the first key exchange.
//
// A packet: uint32 packet_length, byte padding_length, the payload, and at
// least 4 bytes of random padding, the whole (or, where the length goes
// in the clear, all but the length) a multiple of the block size; then
// the MAC or tag. The receiving side learns a packet's length from its
// first bytes (packet_length) before it has the rest (open_packet).

namespace ssh;

import std;
import ssh;
import bignum;
import bignum.aes;
import bignum.gcm;
import bignum.chacha20;
import bignum.hmac;
import bignum.ct;
import bignum.entropy;

let CIPHER_NONE: i64 = 0;
let CIPHER_CHACHA20_POLY1305: i64 = 1;
let CIPHER_AES_GCM: i64 = 2;
let CIPHER_AES_CTR: i64 = 3;

// The cipher and MAC names this package implements, Go's order.
let CIPHERS: const u8[:] = "aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr";
let MACS: const u8[:] = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";

// The largest packet accepted: RFC 4253 §6.1 asks for 35000 bytes; OpenSSH
// and Go take 256 KB.
let MAX_PACKET: i64 = 262144;

// One direction's protection: the cipher, its key and IV (GCM's fixed
// part and invocation counter, CTR's counter block), the MAC (its hash,
// 160, 256 or 512, 0 for none, and key, and whether it is encrypt then
// MAC), and the sequence number of the next packet.
struct PacketCipher {
    kind: i64, key: u8[..64], iv: u8[16], mac: i64, mac_key: u8[..64], etm: bool, seq: u32,
    aes: bignum::Aes, gcm: bignum::AesGcm,
}

fn no_cipher() -> PacketCipher {
    var zero: u8[16] = [0; 16];
    PacketCipher { kind: CIPHER_NONE, key: [], iv: [0; 16], mac: 0, mac_key: [], etm: false, seq: 0,
                   aes: bignum::aes_init(zero), gcm: bignum::gcm_init(zero) }
}

// The key and IV lengths of a cipher (an IV of 0 for ChaCha20-Poly1305),
// and false for one this package lacks.
fn cipher_sizes(name: const u8[:]) -> i64, i64, bool {
    if name == "chacha20-poly1305@openssh.com" { return 64, 0, true; }
    if name == "aes128-gcm@openssh.com" { return 16, 12, true; }
    if name == "aes256-gcm@openssh.com" { return 32, 12, true; }
    if name == "aes128-ctr" { return 16, 16, true; }
    if name == "aes192-ctr" { return 24, 16, true; }
    if name == "aes256-ctr" { return 32, 16, true; }
    return 0, 0, false;
}

// Whether a cipher authenticates itself (an AEAD), so no MAC is chosen.
fn is_aead(name: const u8[:]) -> bool { name == "chacha20-poly1305@openssh.com" || name.ends_with("-gcm@openssh.com") }

// A MAC's hash and key length, whether it is encrypt then MAC, and false
// for one this package lacks.
fn mac_sizes(name: const u8[:]) -> i64, i64, bool, bool {
    if name == "hmac-sha2-256-etm@openssh.com" { return 256, 32, true, true; }
    if name == "hmac-sha2-512-etm@openssh.com" { return 512, 64, true, true; }
    if name == "hmac-sha2-256" { return 256, 32, false, true; }
    if name == "hmac-sha2-512" { return 512, 64, false, true; }
    if name == "hmac-sha1" { return 160, 20, false, true; }
    return 0, 0, false, false;
}

// The protection for a negotiated cipher and MAC, from the derived key,
// IV and MAC key.
fn packet_cipher(cipher: const u8[:], mac: const u8[:], key: const u8[:], iv: const u8[:],
                 mac_key: const u8[:]) -> PacketCipher {
    var c = no_cipher();
    c.key.append(key);
    for i in iv.len { c.iv[i] = iv[i]; }
    if cipher == "chacha20-poly1305@openssh.com" {
        c.kind = CIPHER_CHACHA20_POLY1305;
    } else if cipher.ends_with("-gcm@openssh.com") {
        c.kind = CIPHER_AES_GCM;
        c.gcm = bignum::gcm_init(key);
    } else {
        c.kind = CIPHER_AES_CTR;
        c.aes = bignum::aes_init(key);
        let h, kl, etm, ok = mac_sizes(mac);
        assert(ok);
        c.mac = h;
        c.etm = etm;
        c.mac_key.append(mac_key);
    }
    return c;
}

// The block size padding aligns to, and the tag or MAC length.
fn block_size(c: const PacketCipher&) -> i64 { if c.kind == CIPHER_AES_GCM || c.kind == CIPHER_AES_CTR { 16 } else { 8 } }

fn tag_len(c: const PacketCipher&) -> i64 {
    if c.kind == CIPHER_CHACHA20_POLY1305 || c.kind == CIPHER_AES_GCM { return 16; }
    return c.mac / 8;
}

// Whether the packet length goes in the clear (as additional data or
// under the MAC) rather than encrypted with the rest.
fn length_in_clear(c: const PacketCipher&) -> bool { c.kind == CIPHER_AES_GCM || (c.kind == CIPHER_AES_CTR && c.etm) }

fn be32(b: const u8[:], i: i64) -> i64 { (b[i] as i64) << 24 | (b[i + 1] as i64) << 16 | (b[i + 2] as i64) << 8 | b[i + 3] }

// ChaCha20-Poly1305's per-packet nonce: the sequence number, big-endian,
// in the IETF nonce's last 8 bytes (so the 64-bit counter of the original
// ChaCha20 that OpenSSH uses is the 32-bit counter here, and the rest 0).
fn chacha_nonce(seq: u32) -> u8[12] {
    var n: u8[12] = [0; 12];
    for i in 4 { n[8 + i] = (seq >> (24 - 8 * i)) as! u8; }
    return n;
}

// GCM's nonce, the fixed part and the invocation counter, which moves on
// after each packet.
fn gcm_nonce(c: const PacketCipher&) -> u8[12] {
    var n: u8[12] = [0; 12];
    for i in 12 { n[i] = c.iv[i]; }
    return n;
}

fn gcm_next(c: PacketCipher&) {
    var carry: u32 = 1;
    var i = 12;
    while i > 4 {
        i--;
        let t: u32 = c.iv[i] + carry;
        c.iv[i] = t as! u8;
        carry = t >> 8;
    }
}

fn mac_of(c: const PacketCipher&, data: const u8[:]) -> u8[>..] {
    var m: u8[>..] = [];
    put_u32(m, c.seq);
    m.append(data);
    return bignum::hmac(c.mac, c.mac_key, m);
}

// One packet with this payload, protected; the sequence number moves on.
fn seal_packet(c: PacketCipher&, payload: const u8[:]) -> u8[>..] {
    let bs = block_size(c);
    // The length the padding aligns: the whole packet, or all but its
    // length where that goes in the clear (and for ChaCha20-Poly1305,
    // where OpenSSH aligns all but the length too).
    let aligned = if length_in_clear(c) || c.kind == CIPHER_CHACHA20_POLY1305 { 1 + payload.len } else { 5 + payload.len };
    var npad = bs - aligned % bs;
    if npad < 4 { npad += bs; }
    var out: u8[>..] = [];
    put_u32(out, (1 + payload.len + npad) as! u32);
    out.push(npad as! u8);
    out.append(payload);
    let start = out.len;
    out.resize(start + npad, 0);
    bignum::random_bytes(out[start..]);
    if c.kind == CIPHER_CHACHA20_POLY1305 {
        let nonce = chacha_nonce(c.seq);
        bignum::chacha20_xor(c.key[32..64], 0, nonce, out[..4]);
        let poly_key = bignum::chacha20_block(c.key[..32], 0, nonce);
        bignum::chacha20_xor(c.key[..32], 1, nonce, out[4..]);
        out.append(bignum::poly1305(poly_key[..32], out));
    } else if c.kind == CIPHER_AES_GCM {
        let nonce = gcm_nonce(c);
        let tag = bignum::gcm_encrypt(c.gcm, nonce, out[..4], out[4..]);
        out.append(tag);
        gcm_next(c);
    } else if c.kind == CIPHER_AES_CTR {
        if c.etm {
            bignum::aes_ctr_xor(c.aes, c.iv, out[4..], false);
            out.append(mac_of(c, out));
        } else {
            let mac = mac_of(c, out);
            bignum::aes_ctr_xor(c.aes, c.iv, out, false);
            out.append(mac);
        }
    }
    c.seq++;
    return out;
}

// The bytes the next packet takes, from the first of them: 0 while more
// are needed to tell, -1 for a length no packet has. Nothing changes.
fn packet_length(c: const PacketCipher&, buf: const u8[:]) -> i64 {
    let first = if length_in_clear(c) || c.kind != CIPHER_AES_CTR { 4 } else { 16 };
    if buf.len < first { return 0; }
    var len: i64 = 0;
    if c.kind == CIPHER_CHACHA20_POLY1305 {
        var l: u8[4] = [0; 4];
        for i in 4 { l[i] = buf[i]; }
        bignum::chacha20_xor(c.key[32..64], 0, chacha_nonce(c.seq), l);
        len = be32(l, 0);
    } else if c.kind == CIPHER_AES_CTR && !c.etm {
        var blk: u8[16] = [0; 16];
        for i in 16 { blk[i] = buf[i]; }
        var cb = c.iv;
        bignum::aes_ctr_xor(c.aes, cb, blk, false);
        len = be32(blk, 0);
    } else {
        len = be32(buf, 0);
    }
    let bs = block_size(c);
    let aligned = if length_in_clear(c) || c.kind == CIPHER_CHACHA20_POLY1305 { len } else { len + 4 };
    if len < 5 || len > MAX_PACKET || (c.kind != CIPHER_NONE && aligned % bs != 0) { return -1; }
    return 4 + len + tag_len(c);
}

// The payload of one whole packet (packet_length bytes), and false when it
// does not authenticate or is malformed; the sequence number moves on
// only for one that opens.
fn open_packet(c: PacketCipher&, pkt: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let tl = tag_len(c);
    if pkt.len < 4 + 5 + tl { return out, false; }
    var p: u8[>..] = [];
    p.append(pkt[..pkt.len - tl]);
    let tag = pkt[pkt.len - tl..];
    var good = true;
    if c.kind == CIPHER_CHACHA20_POLY1305 {
        let nonce = chacha_nonce(c.seq);
        let poly_key = bignum::chacha20_block(c.key[..32], 0, nonce);
        let want = bignum::poly1305(poly_key[..32], p);
        good = bignum::ct_eq_bytes(want, tag) == 1;
        if good {
            bignum::chacha20_xor(c.key[32..64], 0, nonce, p[..4]);
            bignum::chacha20_xor(c.key[..32], 1, nonce, p[4..]);
        }
    } else if c.kind == CIPHER_AES_GCM {
        let nonce = gcm_nonce(c);
        let aad: u8[4] = [p[0], p[1], p[2], p[3]];
        good = bignum::gcm_decrypt(c.gcm, nonce, aad, p[4..], tag);
        if good { gcm_next(c); }
    } else if c.kind == CIPHER_AES_CTR {
        if c.etm {
            good = bignum::ct_eq_bytes(mac_of(c, p), tag) == 1;
            if good { bignum::aes_ctr_xor(c.aes, c.iv, p[4..], false); }
        } else {
            var cb = c.iv;
            bignum::aes_ctr_xor(c.aes, cb, p, false);
            good = bignum::ct_eq_bytes(mac_of(c, p), tag) == 1;
            if good { c.iv = cb; }
        }
    }
    if !good { return out, false; }
    let len = be32(p, 0);
    let npad: i64 = p[4];
    if len + 4 != p.len || npad < 4 || npad + 1 > len { return out, false; }
    out.append(p[5..p.len - npad]);
    c.seq++;
    return out, true;
}
