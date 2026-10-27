// ssh.cipher and ssh.kex, between this package's two sides in memory:
// - every cipher (with each MAC for AES-CTR) seals packets of several
//   sizes that the other side's packet_length measures from their first
//   bytes and open_packet opens, in sequence, with the padding rules; a
//   changed byte anywhere, or a packet out of sequence, does not open;
// - every key exchange gives both sides the same K, and the derived keys
//   are as long as asked and differ by letter.
import std;
import ssh from "..";
import bignum from "../../bigmongoose.git";
import asn1 from "../../asn1goose.git";
import x509 from "../../x509goose.git";
import ssh.cipher;
import ssh.kex;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn pair(cipher: const u8[:], mac: const u8[:]) -> ssh::PacketCipher, ssh::PacketCipher {
    let kl, il, ok = ssh::cipher_sizes(cipher);
    let h, ml, etm, okm = ssh::mac_sizes(mac);
    var key: u8[>..] = [];
    key.resize(kl, 0);
    bignum::random_bytes(key);
    var iv: u8[>..] = [];
    iv.resize(il, 0);
    bignum::random_bytes(iv);
    var mk: u8[>..] = [];
    mk.resize(ml, 0);
    bignum::random_bytes(mk);
    let a = ssh::packet_cipher(cipher, mac, key, iv, mk);
    let b = ssh::packet_cipher(cipher, mac, key, iv, mk);
    return a, b;
}

fn ciphers() {
    let names: const u8[:][7] = ["none", "chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com",
                                 "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"];
    let macs: const u8[:][5] = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256",
                                "hmac-sha2-512", "hmac-sha1"];
    for name in names {
        for mac in macs {
            let ctr = name.ends_with("-ctr");
            if !ctr && mac != macs[0] { continue; }
            let suffix: u8[>..] = if ctr { str(" ", mac) } else { "" };
            let label = str(name, suffix);
            var tx = ssh::no_cipher();
            var rx = ssh::no_cipher();
            if name != "none" {
                let a, b = pair(name, mac);
                tx = a;
                rx = b;
            }
            let sizes: i64[6] = [0, 1, 15, 16, 100, 40000];
            var ok = true;
            for n in sizes {
                var payload: u8[>..] = [];
                for i in n { payload.push((i * 13 + n) as! u8); }
                let pkt = ssh::seal_packet(tx, payload);
                // The length from the first bytes alone.
                let want = ssh::packet_length(rx, pkt[..16]);
                ok = ok && want == pkt.len && ssh::packet_length(rx, pkt[..3]) == 0;
                // The padding: at least 4, aligned.
                let got, oko = ssh::open_packet(rx, pkt);
                ok = ok && oko && got == payload;
            }
            check(str("round trip ", label), ok && tx.seq == 6 && rx.seq == 6);
            if name == "none" { continue; }
            // A changed byte at the start, in the middle and in the tag.
            let pkt = ssh::seal_packet(tx, "some payload, long enough to cover a block or two");
            var bad = 0;
            let positions: i64[3] = [5, 20, 0];
            for at in positions {
                var copy_pkt = copy(pkt);
                let i = if at == 0 { copy_pkt.len - 1 } else { at };
                copy_pkt[i] ^= 0x40;
                var r2 = rx;
                let got, oko = ssh::open_packet(r2, copy_pkt);
                if !oko { bad++; }
            }
            check(str("changed ", label), bad == 3);
            // Out of sequence: the next packet before this one.
            let pkt2 = ssh::seal_packet(tx, "the next one");
            var r3 = rx;
            let g3, ok3 = ssh::open_packet(r3, pkt2);
            check(str("out of sequence ", label), !ok3);
            let g4, ok4 = ssh::open_packet(rx, pkt);
            let g5, ok5 = ssh::open_packet(rx, pkt2);
            check(str("in sequence ", label), ok4 && ok5 && g5 == "the next one");
        }
    }
}

fn kexes() {
    let names: const u8[:][9] = ["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org",
                                 "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
                                 "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
                                 "diffie-hellman-group14-sha1"];
    for name in names {
        var c, okc = ssh::kex_method(name);
        var s, oks = ssh::kex_method(name);
        check(str("method ", name), okc && oks && ssh::has_name(ssh::KEX_SUPPORTED, name));
        ssh::kex_keygen(c);
        let ks, ok1 = ssh::kex_server_secret(s, c.mine);
        let kc, ok2 = ssh::kex_client_secret(c, s.mine);
        check(str("agree ", name), ok1 && ok2 && ks == kc && ks.len > 16);
        let h = ssh::exchange_hash(c, "SSH-2.0-a", "SSH-2.0-b", "ic", "is", "hostkey", c.mine, s.mine, kc);
        check(str("hash ", name), h.len == c.hash / 8);
        let k1 = ssh::derive_key(c.hash, kc, h, 'C', h, 64);
        let k2 = ssh::derive_key(c.hash, kc, h, 'D', h, 64);
        check(str("derive ", name), k1.len == 64 && k2.len == 64 && k1 != k2 &&
              ssh::derive_key(c.hash, kc, h, 'C', h, 16) == k1[..16]);
        // A bad public value is refused.
        var bad = copy(s.mine);
        if name.starts_with("diffie") { bad.clear(); bad.push(1); } else { bad.resize(bad.len - 1); }
        let kb, okb = ssh::kex_client_secret(c, bad);
        check(str("bad value ", name), !okb);
    }
    let x, okx = ssh::kex_method("diffie-hellman-group1-sha1");
    check("unknown method", !okx);
}

fn main() {
    ciphers();
    kexes();
    print("transport: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
