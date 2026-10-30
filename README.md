# ssh

SSH (RFC 4251-4254) for the Goose language, as Go's
`golang.org/x/crypto/ssh` has it, on [bignum](../bigmongoose.git) for the
cryptography and [x509](../x509goose.git) and [asn1](../asn1goose.git) for
key files. Nothing here does I/O.

Five programs come with it: `goose-ssh`, a client, `goose-sshd`, a
server, `goose-scp` and `goose-sftp-server`, and `goose-ssh-keygen` (see
below).

- **`ssh`**: message numbers, the wire encoding (integers, strings, mpints,
  name-lists, RFC 4251 §5) and algorithm negotiation.
- **`ssh.keys`**: public keys and signatures: Ed25519 (RFC 8709), ECDSA on
  P-256, P-384 and P-521 (RFC 5656), RSA with rsa-sha2-256, rsa-sha2-512
  (RFC 8332) and ssh-rsa; authorized_keys lines with options; private keys
  in OpenSSH's format (openssh-key-v1), passphrase-protected with
  bcrypt_pbkdf under any of OpenSSH's key file ciphers (aes128/192/256-ctr
  and -cbc, aes128/256-gcm@openssh.com, chacha20-poly1305@openssh.com) or
  not, read and written, and PEM (PKCS #1, SEC 1, PKCS #8); SHA-256 and
  MD5 fingerprints; key generation.
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
  (RFC 8308), rekeying (on request, after `rekey_bytes` sent or received,
  1 GB by default, or 2^31 packets either way, as Go, checked as each
  packet goes out and as input comes in; past 2^32 − 2 packets
  under one key, where ChaCha20-Poly1305's nonce would repeat, the
  connection fails; between its KEXINIT and its NEWKEYS a side sends only
  the exchange's messages, RFC 4253 §7.1, and what else it has waits and
  goes after); the host key against known_hosts lines (patterns,
  hashed entries, ports, @revoked), a fixed key, or put to the application;
  publickey (query, then signature; the server refuses authorized_keys
  lines with options, which it does not enforce), password and keyboard-interactive
  authentication both ways, the client asking for a password only when it
  needs one; channels with flow control (the window opens as data
  arrives, or, held with `channel_hold_window`, as the application reports
  it used with `channel_consumed`, as Go's channels do as they are read), data and stderr, exec, shell,
  pty-req, env, subsystem, window-change, exit-status and exit-signal;
  global requests and their replies, and port forwarding's channels and
  requests (direct-tcpip, tcpip-forward, cancel-tcpip-forward,
  forwarded-tcpip, RFC 4254 §7), the application connecting and listening.
- **`ssh.sftp`**: the SSH File Transfer Protocol, version 3
  (draft-ietf-secsh-filexfer-02) as OpenSSH speaks it, without I/O: every
  request and reply written and read back, attributes, status codes, packet
  framing (at most 256 KiB, as OpenSSH), extensions named in VERSION, and
  ls -l longnames. Where OpenSSH departs from the draft it follows OpenSSH:
  SYMLINK takes the target first.

## The programs

```bash
cd tools
goose build -o goose-ssh ssh.goose
goose build -o goose-sshd sshd.goose
goose build -o goose-ssh-keygen keygen.goose
goose build -o goose-scp scp.goose
goose build -o goose-sftp-server sftp_server.goose

./goose-sshd -p 2222                       # 127.0.0.1:2222, ~/.ssh/authorized_keys
./goose-ssh -p 2222 localhost              # an interactive shell
./goose-ssh user@host.example.com uname -a # a command, its exit status ours
./goose-scp -P 2222 -rp dir localhost:     # a directory to the home directory there
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
For a passphrase-protected key it asks for the passphrase (three tries;
empty skips the key) at the terminal, or runs `$SSH_ASKPASS` as ssh does
(always with `SSH_ASKPASS_REQUIRE=force` or `prefer`, else when there is
no terminal); password prompts likewise.

`goose-sshd` lets in the user running it: `-p port` (2222), `-a address`
(127.0.0.1), `-h host_key_file` (`./goose_host_ed25519_key`, made on first
start with mode 0600; as in OpenSSH, one that others may read is
refused), `-k authorized_keys` (`~/.ssh/authorized_keys`; a line with
options, `command=`, `from=`, `restrict` and the like, lets nobody in,
since they are not enforced), `-P
password_file` ("user:password" lines, plain or bcrypt), `-u user`,
`-b banner`, `-s sftp_server` (by default `goose-sftp-server` beside
goose-sshd), `-g`, `-v`. Each connection is a process of its own; a session
runs a command or the user's shell, on a pty when asked, in the user's home
directory, and ends with its exit status; the `sftp` subsystem runs the
SFTP server. It connects the client's -L and -D channels to their targets,
and listens for -R on the loopback address (on the address asked for with
`-g`, as OpenSSH's GatewayPorts). tools/net.c is their operating-system part (sockets, the terminal,
processes), and tools/fs.c the file system's, for macOS and Linux.

`goose-scp` copies files as OpenSSH's scp does by default (over SFTP):
`[-r] [-p] [-q] [-v] [-P port] [-i keyfile] [-o option=value] source...
target`, a remote file being `[user@]host:path`, with goose-ssh's login,
keys, known_hosts and `-o` options. All the sources are local and the
target remote, or the sources are on one host and the target local; a
target that is a directory takes each source by its name, and several
sources need one. A remote path starts from the home directory, `~` is
expanded by the server (expand-path@openssh.com), and a remote source's last
part may be a pattern (`*`, `?`, `[...]`). `-r` copies directories,
following symbolic links; `-p` keeps times and modes (otherwise a new file
gets its source's mode under the umask, as scp). Transfers keep 64 requests
of 32 KiB in flight, as OpenSSH's. A file that fails is reported and the
others still copied; the status is then 1. Not supported: copies between
two remote hosts, the legacy scp protocol (`-O`; OpenSSH's `scp -O` to
goose-sshd works through the remote `scp`), the progress meter (`-q` is
taken and changes nothing), `-l`, `-3`, `-J`.

`goose-sftp-server` serves SFTP on stdin and stdout as OpenSSH's
sftp-server, with the user's own file access: goose-sshd runs it, and so
can OpenSSH's sshd (`Subsystem sftp /path/goose-sftp-server`). Its
extensions are OpenSSH's (posix-rename, statvfs, fstatvfs, hardlink, fsync,
lsetstat, limits, expand-path, users-groups-by-id, copy-data,
home-directory), at the versions OpenSSH gives them. It answers as
OpenSSH's does, request for request (`scripts/sftp_raw.py`, below), except
where OpenSSH's ends the session or does not answer: a request that does
not parse, or whose path holds a NUL, gets a bad message; an unknown packet
type gets "unsupported", as the draft has it (OpenSSH's sends nothing). RENAME
does not replace a file, as the draft says (a link, then an unlink, as
OpenSSH); posix-rename@openssh.com does. REALPATH takes a path whose last
part does not exist yet, as OpenSSH's (OpenBSD's realpath). At most 64
handles are open at once, each named by its slot and a generation, so a
closed handle never names the slot's next use. `-e` or `-v` logs requests
to stderr.

`goose-ssh-keygen` makes key files as ssh-keygen does: `-t ed25519`
(the default), `ecdsa` (`-b 256`, `384`, `521`) or `rsa` (`-b`, 3072),
`-C comment`, `-N passphrase` (else asked twice; empty for none), `-Z
cipher` (aes256-ctr), `-a rounds` (16), `-f file` (`~/.ssh/id_<type>`),
the key in OpenSSH's format with mode 0600 and `file.pub` beside it. `-y
[-P passphrase] -f file` prints the public line, `-p [-P old] [-N new] -f
file` changes the passphrase, `-l [-E sha256|md5] -f file` prints the
fingerprint.

## Tests

```bash
python3 scripts/run_tests.py            # at -O0, -O2 and --debug
python3 scripts/run_tests.py --native   # also built with the C compiler
python3 scripts/interop.py              # live, against OpenSSH and Go (below)
python3 scripts/gen_keys.py             # remake test/vectors (ssh-keygen, openssl, Go)
tools/gossh.sh <mode> ...               # Go's side by hand (modes in tools/gossh/main.go)
```

They take the compiler from `$GOOSE`, else `goose` on PATH, else
`../goose.git/build/goose` (run_tests.py also takes `--goose`), and bigmongoose.git, asn1goose.git and
x509goose.git beside this repository. interop.py also needs OpenSSH
(`ssh` and `ssh-keygen` from PATH; `sshd` from `$SSHD`, else the
`sbin/sshd` beside that `ssh`, else `/usr/sbin/sshd`), Go with golang.org/x/crypto v0.55.0 in the
module cache, `curl` and Python's http.server; it runs everything as you,
on free ports of 127.0.0.1, and leaves nothing running.

- `keys`: the wire encoding and negotiation; every key file of
  `test/vectors` (made by `scripts/gen_keys.py` with ssh-keygen and
  OpenSSL) parses to its `.pub` line's key with ssh-keygen's fingerprints;
  Go's signatures (`tools/gossh`, x/crypto/ssh) verify for every
  algorithm, and Ed25519 and RSA signatures made here equal Go's; changed
  signatures, other algorithms and other keys are refused; authorized_keys
  options and comments; keys written in OpenSSH's format read back;
  passphrase-protected keys, ssh-keygen's under each of the nine key file
  ciphers and one of Go's: refused without the passphrase or with another,
  read with it, written here under the same cipher and read back, a
  changed tag or a shortened file refused.
- `transport`: every cipher and MAC seals packets of 0 to 40000 bytes that
  the other side measures from their first bytes and opens in sequence;
  a changed byte or a packet out of order does not open; every key
  exchange agrees on K both ways and refuses a bad public value.
- `conn`: this client and server in memory: every key exchange, cipher,
  MAC and host key type; each kind of login, refused ones, a password
  asked for; every known_hosts case and the ask mode, which sends nothing
  until the host key is accepted; sessions with exec, env and pty, 3 MB
  each way through the windows, rekeys from both sides, disconnect;
  rekeying on bytes received alone and on the packet count, and the
  connection failed at the packet limit, sending and receiving; a held
  window that lets in one window and then only what was used; window
  adjustments wanted during either side's rekey held until its NEWKEYS;
  a rekey started by sending alone (global requests, no input).
- `sftp`: every SFTP request and reply written and read back field by
  field, INIT and READ and ATTRS byte for byte, SYMLINK in OpenSSH's order,
  STATUS with OpenSSH's messages (and without a language tag), NAME's
  count, attributes with each field and extended pairs skipped, truncated
  ones refused at every length, packet framing (partial, two at once,
  empty, one byte over 256 KiB), ls -l longnames (set-id and sticky bits,
  recent and old dates) and dates from day counts.
- `forward`: port forwarding in memory: direct-tcpip with its target and
  originator, data, EOF and close, and a refused one; tcpip-forward on port
  0 and the port in the reply; forwarded-tcpip channels from the server;
  cancel-tcpip-forward; an unknown global request refused; replies in
  order; 40 channels at once.

`scripts/interop.py` runs live connections on 127.0.0.1 (352 cases):
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
And protected keys, the passphrase through SSH_ASKPASS: goose-ssh-keygen's
used by goose-ssh (with OpenSSH sshd and goose-sshd) and by OpenSSH ssh,
ssh-keygen's ChaCha20-Poly1305 and AES-GCM ones by goose-ssh, a wrong
passphrase refused; goose-ssh-keygen's keys under every cipher read by
ssh-keygen (and by Go, for the AES-256 CTR and CBC ones it reads), and
its fingerprints equal to ssh-keygen's.

And SFTP: `scripts/sftp_raw.py` sends goose-sftp-server and OpenSSH's
sftp-server the same 100 requests, byte by byte, and compares their replies
(stale and malformed handles, EXCL and APPEND, reads past the end and cut
at the limit, links, RENAME onto a file and posix-rename, directories, NUL
and over-long paths, every attribute, every extension); one `sftp -D` batch
(put, get, reput, reget, -r, rename, ln, chmod, df, failures) to each,
transcripts and trees compared; goose-scp to goose-sshd, to OpenSSH sshd
with its sftp-server and to OpenSSH sshd with goose-sftp-server (5 MB and
empty files both ways, -rp with times and modes, into a directory, several
sources, patterns, `~` and relative paths, a missing source, a directory
without -r, an unwritable destination); OpenSSH's scp -rp and an sftp batch
to goose-sshd and to goose-sftp-server.

`tools/gossh` builds offline from the module cache
(`GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off`).
