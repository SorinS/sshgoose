# ssh

SSH (RFC 4251-4254) for the Goose language, as Go's
`golang.org/x/crypto/ssh` has it, on [bignum](../bigmongoose.git) for the
cryptography and [x509](../x509goose.git) and [asn1](../asn1goose.git) for
key files. Nothing here does I/O.

Work in progress: the wire encoding, keys, the packet layer and the key
exchanges are done; the connection (handshake, authentication, channels)
comes next.

- **`ssh`**: message numbers, the wire encoding (integers, strings, mpints,
  name-lists, RFC 4251 §5) and algorithm negotiation.
- **`ssh.keys`**: public keys and signatures: Ed25519 (RFC 8709), ECDSA on
  P-256, P-384 and P-521 (RFC 5656), RSA with rsa-sha2-256, rsa-sha2-512
  (RFC 8332) and ssh-rsa; authorized_keys lines with options; private keys
  in OpenSSH's format (openssh-key-v1, unencrypted for now) and PEM
  (PKCS #1, SEC 1, PKCS #8); SHA-256 and MD5 fingerprints; key generation.
- **`ssh.cipher`**: the binary packet protocol (RFC 4253 §6) under
  chacha20-poly1305@openssh.com, aes128/256-gcm@openssh.com (RFC 5647),
  and aes128/192/256-ctr (RFC 4344) with hmac-sha2-256, hmac-sha2-512 or
  hmac-sha1, MAC then encrypt or the -etm@openssh.com forms.
- **`ssh.kex`**: mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex),
  curve25519-sha256 (RFC 8731), ecdh-sha2-nistp256/384/521 (RFC 5656),
  diffie-hellman-group14-sha256, group16-sha512 and group14-sha1
  (RFC 8268, over `bignum.ffdh`); the exchange hash and key derivation
  (RFC 4253 §7.2). The defaults are Go's.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
```

- `keys`: the wire encoding and negotiation; every key file of
  `test/vectors` (made by `scripts/gen_keys.py` with ssh-keygen and
  OpenSSL) parses to its `.pub` line's key with ssh-keygen's fingerprints;
  Go's signatures (`scripts/gossh`, x/crypto/ssh) verify for every
  algorithm, and Ed25519 and RSA signatures made here equal Go's; changed
  signatures, other algorithms and other keys are refused; authorized_keys
  options and comments; keys written in OpenSSH's format read back.
- `transport`: every cipher and MAC seals packets of 0 to 40000 bytes that
  the other side measures from their first bytes and opens in sequence;
  a changed byte or a packet out of order does not open; every key
  exchange agrees on K both ways and refuses a bad public value.

`scripts/gossh` builds offline from the module cache
(`GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`).
