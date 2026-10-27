# ssh

SSH (RFC 4251-4254) for the Goose language, as Go's
`golang.org/x/crypto/ssh` has it, on [bignum](../bigmongoose.git) for the
cryptography and [x509](../x509goose.git) and [asn1](../asn1goose.git) for
key files. Nothing here does I/O.

Two programs come with it: `goose-ssh`, a client, and `goose-sshd`, a
server (see below).

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
- **`ssh.conn`**: connections, client and server, without I/O: feed in the
  bytes that arrive, get the bytes to send and a stream of events. Version
  exchange, negotiation, strict key exchange (Terrapin), server-sig-algs
  (RFC 8308), rekeying; the host key against known_hosts lines (patterns,
  hashed entries, ports, @revoked), a fixed key, or put to the application;
  publickey (query, then signature), password and keyboard-interactive
  authentication both ways, the client asking for a password only when it
  needs one; channels with flow control, data and stderr, exec, shell,
  pty-req, env, subsystem, window-change, exit-status and exit-signal;
  global requests and their replies, and port forwarding's channels and
  requests (direct-tcpip, tcpip-forward, cancel-tcpip-forward,
  forwarded-tcpip, RFC 4254 §7), the application connecting and listening.

## The programs

```bash
cd tools
goose build -o goose-ssh ssh.goose
goose build -o goose-sshd sshd.goose

./goose-sshd -p 2222                       # 127.0.0.1:2222, ~/.ssh/authorized_keys
./goose-ssh -p 2222 localhost              # an interactive shell
./goose-ssh user@host.example.com uname -a # a command, its exit status ours
```

`goose-ssh` works as OpenSSH's `ssh` is used: `[user@]host`, `-p`, `-l`,
`-i keyfile` (else `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`), `-t`/`-T`,
`-v`, and `-o` with `StrictHostKeyChecking` (ask, the default; `yes`,
`accept-new`, `no`), `UserKnownHostsFile`, `KexAlgorithms`, `Ciphers`,
`MACs` and `HostKeyAlgorithms`. It checks `~/.ssh/known_hosts`, asks about
a host it does not know and adds it, asks for a password only when the
server takes one and no key worked, runs a command or a shell (on a pty,
the terminal raw, its size passed on), and exits with the remote status.
It forwards ports as OpenSSH does: `-L [bind:]port:host:hostport` (a local
port, the server connecting), `-R [bind:]port:host:hostport` (a port on the
server, connected from here; port 0 has the server pick one, which it
prints), `-D [bind:]port` (a SOCKS5 proxy), and `-N` for forwards alone.
Passphrase-protected keys are not read yet.

`goose-sshd` lets in the user running it: `-p port` (2222), `-a address`
(127.0.0.1), `-h host_key_file` (`./goose_host_ed25519_key`, made on first
start), `-k authorized_keys` (`~/.ssh/authorized_keys`), `-P
password_file` ("user:password" lines, plain or bcrypt), `-u user`,
`-b banner`, `-g`, `-v`. Each connection is a process of its own; a session
runs a command or the user's shell, on a pty when asked, and ends with its
exit status. It connects the client's -L and -D channels to their targets,
and listens for -R on the loopback address (on the address asked for with
`-g`, as OpenSSH's GatewayPorts). tools/net.c is their operating-system part (sockets, the terminal,
processes), for macOS and Linux.

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
- `conn`: this client and server in memory: every key exchange, cipher,
  MAC and host key type; each kind of login, refused ones, a password
  asked for; every known_hosts case and the ask mode, which sends nothing
  until the host key is accepted; sessions with exec, env and pty, 3 MB
  each way through the windows, rekeys from both sides, disconnect.
- `forward`: port forwarding in memory: direct-tcpip with its target and
  originator, data, EOF and close, and a refused one; tcpip-forward on port
  0 and the port in the reply; forwarded-tcpip channels from the server;
  cancel-tcpip-forward; an unknown global request refused; replies in
  order; 40 channels at once.

`scripts/interop.py` runs live connections on 127.0.0.1 (150 cases):
goose-ssh against an OpenSSH sshd (10.3, run as the user, with DH and
ssh-rsa enabled again), Go's x/crypto/ssh server and goose-sshd, with
every key exchange, cipher and MAC, every host key type, Ed25519 and RSA
user keys, 5 MB through cat, stderr and exit status, and the known_hosts
cases; OpenSSH's ssh against goose-sshd likewise, with password and
keyboard-interactive logins and a pty; Go's client against goose-sshd.
And port forwarding, a 1 MB file fetched twice over HTTP through each
forward: goose-ssh's -L, -D and -R through OpenSSH sshd and goose-sshd, -L
and -D through Go's server; OpenSSH ssh's -L, -D, -R and -R with port 0
through goose-sshd; Go's client's direct-tcpip through goose-sshd.

`scripts/gossh` builds offline from the module cache
(`GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`).
