#!/usr/bin/env python3
"""Live SSH interop over 127.0.0.1: this package's client (tools/ssh.goose,
goose-ssh) and server (tools/sshd.goose, goose-sshd) against OpenSSH's sshd
and ssh, Go's x/crypto/ssh (tools/gossh), and each other.

It builds goose-ssh, goose-sshd, goose-ssh-keygen and gossh, makes host and user keys with
ssh-keygen, and starts three servers on free ports: an OpenSSH sshd running
as this user (its own config, DH and ssh-rsa enabled again, since OpenSSH
10 no longer offers them), goose-sshd, and Go's. Then:

- goose-ssh to OpenSSH sshd, Go and goose-sshd: every key exchange, cipher
  and MAC, every host key type (OpenSSH), Ed25519 and RSA user keys, 5 MB
  through cat (OpenSSH, goose-sshd), stdin, stderr and exit status;
  known_hosts: an unknown host refused under StrictHostKeyChecking=yes,
  added under accept-new, then known; a changed key refused;
- OpenSSH ssh to goose-sshd: every key exchange, cipher and MAC, Ed25519
  and RSA keys, password and keyboard-interactive (through SSH_ASKPASS), a
  pty, 5 MB through cat, exit status;
- Go's client to goose-sshd: key exchanges, ciphers, a password.
- Passphrase-protected keys (the passphrase through SSH_ASKPASS):
  goose-ssh-keygen's used by goose-ssh with OpenSSH sshd and goose-sshd,
  and by OpenSSH ssh; ssh-keygen's (ChaCha20-Poly1305, AES-GCM) used by
  goose-ssh; a wrong passphrase refused; goose-ssh-keygen's under every
  key file cipher read by ssh-keygen (and by Go, for the AES-256 CTR and
  CBC ones it reads), its fingerprints the same as ssh-keygen's.
- Port forwarding, a 1 MB file fetched twice over HTTP through each forward:
  goose-ssh's -L, -D (SOCKS5) and -R through OpenSSH sshd and goose-sshd,
  -L and -D through Go's server; OpenSSH ssh's -L, -D, -R and -R with port
  0 through goose-sshd; Go's client's direct-tcpip through goose-sshd.
- SFTP: scripts/sftp_raw.py's requests to goose-sftp-server and OpenSSH's
  sftp-server, their replies compared; one sftp batch (put, get, reput,
  reget, -r, mkdir, rename, ln, chmod, df, errors) through `sftp -D` to
  each, the transcripts and the trees left compared; goose-scp to
  goose-sshd, to OpenSSH sshd with its sftp-server and to OpenSSH sshd with
  goose-sftp-server (5 MB and empty files both ways, -r, -p, several
  sources, a pattern, ~ and relative paths, and refusals); OpenSSH scp and
  sftp to goose-sshd and to goose-sftp-server under OpenSSH sshd.

    python3 scripts/interop.py [--goose PATH]
"""

import hashlib
import os
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GO_ENV = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOSUMDB": "off"}
USER = os.environ.get("USER") or os.environ.get("LOGNAME")
PASSPHRASE = "an interop passphrase"
KEY_FILE_CIPHERS = ["aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
                    "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"]

KEXES = ["mlkem768x25519-sha256", "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
         "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"]
AEADS = ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]
CTRS = ["aes128-ctr", "aes192-ctr", "aes256-ctr"]
MACS = ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else f"\n      {detail}"))


def find_sshd():
    # $SSHD, else the sshd of the ssh on PATH (sbin beside its bin), else
    # the system's.
    if os.environ.get("SSHD"):
        return os.environ["SSHD"]
    ssh = shutil.which("ssh")
    if ssh:
        cand = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(ssh))), "sbin", "sshd")
        if os.path.isfile(cand):
            return cand
    return "/usr/sbin/sshd"


def find_sftp_server():
    # $SFTP_SERVER, else the one beside sshd (libexec), else the usual places.
    if os.environ.get("SFTP_SERVER"):
        return os.environ["SFTP_SERVER"]
    sshd = os.path.realpath(find_sshd())
    for cand in (os.path.join(os.path.dirname(os.path.dirname(sshd)), "libexec", "sftp-server"),
                 "/usr/libexec/sftp-server", "/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server"):
        if os.path.isfile(cand):
            return cand
    sys.exit("no OpenSSH sftp-server found: set SFTP_SERVER")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run(cmd, stdin=b"", env=None, timeout=120):
    p = subprocess.run(cmd, input=stdin, capture_output=True, env=env, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def main():
    goose = sys.argv[sys.argv.index("--goose") + 1] if "--goose" in sys.argv else \
        os.environ.get("GOOSE") or shutil.which("goose") or os.path.join(ROOT, "..", "goose.git", "build", "goose")
    t = tempfile.mkdtemp()
    k = lambda name: os.path.join(t, name)
    for tool, out in (("ssh.goose", "goose-ssh"), ("sshd.goose", "goose-sshd"), ("keygen.goose", "goose-ssh-keygen"),
                      ("sftp_server.goose", "goose-sftp-server"), ("scp.goose", "goose-scp")):
        subprocess.run([goose, "build", "-o", k(out), os.path.join(ROOT, "tools", tool)], check=True, capture_output=True)
    subprocess.run(["go", "build", "-o", k("gossh"), "."], cwd=os.path.join(ROOT, "tools", "gossh"), check=True,
                   env=GO_ENV)
    for name, args in (("host_ed25519", ["-t", "ed25519"]), ("host_ecdsa", ["-t", "ecdsa"]),
                       ("host_rsa", ["-t", "rsa", "-b", "2048"]), ("user_ed25519", ["-t", "ed25519"]),
                       ("user_rsa", ["-t", "rsa", "-b", "2048"]), ("other_ed25519", ["-t", "ed25519"])):
        subprocess.run(["ssh-keygen", "-q", *args, "-N", "", "-f", k(name)], check=True)
    # Protected user keys: goose-ssh-keygen's, and ssh-keygen's under two AEADs.
    subprocess.run([k("goose-ssh-keygen"), "-t", "ed25519", "-N", PASSPHRASE, "-f", k("enc_goose")], check=True,
                   capture_output=True)
    for name, args in (("enc_chacha", ["-t", "ecdsa", "-Z", "chacha20-poly1305@openssh.com"]),
                       ("enc_gcm", ["-t", "ed25519", "-Z", "aes256-gcm@openssh.com"])):
        subprocess.run(["ssh-keygen", "-q", *args, "-N", PASSPHRASE, "-f", k(name)], check=True)
    with open(k("authorized_keys"), "w") as f:
        f.write("".join(open(k(n + ".pub")).read() for n in ("user_ed25519", "user_rsa", "enc_goose", "enc_chacha", "enc_gcm")))
    with open(k("askpass_key"), "w") as f:
        f.write(f"#!/bin/sh\necho '{PASSPHRASE}'\n")
    os.chmod(k("askpass_key"), 0o755)
    with open(k("passwords"), "w") as f:
        f.write(f"{USER}:letmein\n")
    with open(k("askpass"), "w") as f:
        f.write("#!/bin/sh\necho letmein\n")
    os.chmod(k("askpass"), 0o755)
    pub = lambda name: " ".join(open(k(name + ".pub")).read().split()[:2])

    # Private key files are 0600 from the start whatever the umask, and a
    # host key that others may read is refused, as OpenSSH does.
    mode = lambda name: stat.S_IMODE(os.stat(k(name)).st_mode)
    old_umask = os.umask(0)
    try:
        subprocess.run([k("goose-ssh-keygen"), "-t", "ed25519", "-N", "", "-f", k("umask_key")], check=True,
                       capture_output=True)
        check("keygen: a new key is 0600 under umask 000", mode("umask_key") == 0o600, oct(mode("umask_key")))
        rc, _, err = run([k("goose-ssh-keygen"), "-p", "-P", "", "-N", "x", "-f", k("umask_key")])
        check("keygen -p: the rewritten key is 0600", rc == 0 and mode("umask_key") == 0o600, err.decode())
        p_new = free_port()
        s = subprocess.Popen([k("goose-sshd"), "-p", str(p_new), "-h", k("new_host"), "-k", k("authorized_keys")],
                             stderr=subprocess.DEVNULL)
        up = wait_port(p_new)
        s.terminate()
        s.wait()
        check("sshd: a new host key is 0600 under umask 000", up and mode("new_host") == 0o600,
              oct(mode("new_host")) if os.path.exists(k("new_host")) else "no key")
    finally:
        os.umask(old_umask)
    shutil.copy(k("host_ed25519"), k("open_host"))
    os.chmod(k("open_host"), 0o644)
    rc, _, err = run([k("goose-sshd"), "-p", str(free_port()), "-h", k("open_host"), "-k", k("authorized_keys")],
                     timeout=30)
    check("sshd: a host key others may read is refused", rc != 0 and b"too open" in err, err.decode())
    os.symlink(k("host_ed25519"), k("linked_host"))
    rc, _, err = run([k("goose-sshd"), "-p", str(free_port()), "-h", k("linked_host"), "-k", k("authorized_keys")],
                     timeout=30)
    check("sshd: a host key through a symlink is refused", rc != 0 and b"symlink" in err, err.decode())
    # A FIFO with no writer: refused at once as not a regular file, not
    # waited on (open without O_NONBLOCK would block).
    os.mkfifo(k("fifo_host"), 0o600)
    try:
        rc, _, err = run([k("goose-sshd"), "-p", str(free_port()), "-h", k("fifo_host"), "-k", k("authorized_keys")],
                         timeout=10)
        check("sshd: a FIFO host key is refused at once", rc != 0 and b"not a regular file" in err, err.decode())
    except subprocess.TimeoutExpired:
        check("sshd: a FIFO host key is refused at once", False, "blocked for 10 s")
    # A directory, and a key file too long to be one.
    os.mkdir(k("dir_host"), 0o700)
    rc, _, err = run([k("goose-sshd"), "-p", str(free_port()), "-h", k("dir_host"), "-k", k("authorized_keys")],
                     timeout=10)
    check("sshd: a directory as host key is refused", rc != 0 and b"not a regular file" in err, err.decode())
    with open(k("big_host"), "wb") as f:
        f.write(b"x" * 70000)
    os.chmod(k("big_host"), 0o600)
    rc, _, err = run([k("goose-sshd"), "-p", str(free_port()), "-h", k("big_host"), "-k", k("authorized_keys")],
                     timeout=10)
    check("sshd: a host key file too long is refused", rc != 0 and b"too long" in err, err.decode())

    # The servers: OpenSSH's sshd (with its sftp-server), goose-sshd (with
    # goose-sftp-server, found beside it), Go's; and a second OpenSSH sshd
    # whose sftp subsystem is goose-sftp-server.
    p_openssh, p_goose, p_go, p_osftp = free_port(), free_port(), free_port(), free_port()
    sftp_server = find_sftp_server()
    for conf, port, sub, pid in (("sshd_config", p_openssh, sftp_server, "sshd.pid"),
                                 ("sshd_config_gsftp", p_osftp, k("goose-sftp-server"), "sshd2.pid")):
        with open(k(conf), "w") as f:
            f.write(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {k('host_ed25519')}\nHostKey {k('host_ecdsa')}\n"
                    f"HostKey {k('host_rsa')}\nAuthorizedKeysFile {k('authorized_keys')}\nPidFile {k(pid)}\n"
                    "UsePAM no\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                    "KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha1\n"
                    f"MACs +hmac-sha1\nHostKeyAlgorithms +ssh-rsa\nSubsystem sftp {sub}\n")
    servers = [subprocess.Popen([find_sshd(), "-D", "-f", k("sshd_config"), "-E", k("sshd.log")]),
               subprocess.Popen([find_sshd(), "-D", "-f", k("sshd_config_gsftp"), "-E", k("sshd2.log")]),
               subprocess.Popen([k("goose-sshd"), "-p", str(p_goose), "-h", k("host_ed25519"), "-k", k("authorized_keys"),
                                 "-P", k("passwords")], stderr=subprocess.DEVNULL),
               subprocess.Popen([k("gossh"), "server", str(p_go), k("host_ecdsa"), k("authorized_keys"), "gopw"],
                                stdout=subprocess.DEVNULL)]
    try:
        for p in (p_openssh, p_goose, p_go, p_osftp):
            if not wait_port(p):
                sys.exit(f"a server did not start on port {p}")
        known = {p_openssh: f"[127.0.0.1]:{p_openssh} {pub('host_ed25519')}\n"
                            f"[127.0.0.1]:{p_openssh} {pub('host_ecdsa')}\n[127.0.0.1]:{p_openssh} {pub('host_rsa')}\n",
                 p_goose: f"[127.0.0.1]:{p_goose} {pub('host_ed25519')}\n",
                 p_go: f"[127.0.0.1]:{p_go} {pub('host_ecdsa')}\n",
                 p_osftp: f"[127.0.0.1]:{p_osftp} {pub('host_ed25519')}\n"}
        with open(k("known_hosts"), "w") as f:
            f.write("".join(known.values()))

        def gssh(port, *args, key="user_ed25519", stdin=b"", kh=None, env=None):
            cmd = [k("goose-ssh"), "-p", str(port), "-i", k(key), "-o", f"UserKnownHostsFile={kh or k('known_hosts')}",
                   "-o", "StrictHostKeyChecking=yes", *args]
            return run(cmd, stdin, env)

        # A goose-sshd started with SIGHUP and SIGPIPE ignored (as under
        # nohup): its sessions' children still get the default signals,
        # and a session whose client is gone leaves no child behind.
        p_nohup = free_port()
        nohup = subprocess.Popen([k("goose-sshd"), "-p", str(p_nohup), "-h", k("host_ed25519"), "-k", k("authorized_keys")],
                                 stderr=subprocess.DEVNULL,
                                 preexec_fn=lambda: (signal.signal(signal.SIGHUP, signal.SIG_IGN),
                                                     signal.signal(signal.SIGPIPE, signal.SIG_IGN)))
        try:
            check("nohup'd goose-sshd up", wait_port(p_nohup))
            kh_nohup = k("known_hosts_nohup")
            with open(kh_nohup, "w") as f:
                f.write(f"[127.0.0.1]:{p_nohup} {pub('host_ed25519')}\n")
            rc, out, err = gssh(p_nohup, "127.0.0.1", "kill -PIPE $$; echo still here", kh=kh_nohup)
            check("child: SIGPIPE back to its default", rc == 128 + 13 and b"still here" not in out, f"rc {rc} {out!r}")
            marker = "sleep 3017"
            client = subprocess.Popen([k("goose-ssh"), "-p", str(p_nohup), "-i", k("user_ed25519"), "-o",
                                       f"UserKnownHostsFile={kh_nohup}", "127.0.0.1", marker],
                                      stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(50):
                if subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode == 0:
                    break
                time.sleep(0.1)
            started = subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode == 0
            client.kill()
            client.wait()
            gone = False
            for _ in range(150):
                if subprocess.run(["pgrep", "-f", marker], capture_output=True).returncode != 0:
                    gone = True
                    break
                time.sleep(0.1)
            left = subprocess.run(["ps", "-axo", "pid,ppid,stat,command"], capture_output=True, text=True).stdout
            left = "\n".join(l for l in left.splitlines() if marker in l or "goose-sshd" in l)
            check("client killed: the session's child gone", started and gone, f"started {started}; left:\n{left}")
            subprocess.run(["pkill", "-f", marker], capture_output=True)
        finally:
            nohup.terminate()
            nohup.wait()

        big = os.urandom(5_000_000)
        digest = hashlib.sha256(big).hexdigest()
        # goose-ssh to each server.
        for port, name in ((p_openssh, "OpenSSH sshd"), (p_go, "Go"), (p_goose, "goose-sshd")):
            is_go = port == p_go
            cmd = "x" if is_go else "echo out; echo err >&2; exit 7"
            want_out = b"go ran: x" if is_go else b"out\n"
            want_code = 6 if is_go else 7
            for kex in KEXES:
                rc, out, err = gssh(port, "-o", f"KexAlgorithms={kex}", "127.0.0.1", cmd)
                check(f"goose-ssh -> {name}, {kex}", rc == want_code and out == want_out, (rc, out, err))
            for c in AEADS:
                rc, out, err = gssh(port, "-o", f"Ciphers={c}", "127.0.0.1", cmd, key="user_rsa")
                check(f"goose-ssh -> {name}, {c}, RSA key", rc == want_code and out == want_out, (rc, out, err))
            for c in CTRS:
                for m in MACS:
                    rc, out, err = gssh(port, "-o", f"Ciphers={c}", "-o", f"MACs={m}", "127.0.0.1", cmd)
                    check(f"goose-ssh -> {name}, {c} {m}", rc == want_code and out == want_out, (rc, out, err))
            if not is_go:
                rc, out, err = gssh(port, "127.0.0.1", "cat", stdin=big)
                check(f"goose-ssh -> {name}, 5 MB through cat",
                      rc == 0 and hashlib.sha256(out).hexdigest() == digest, (rc, len(out), err))
                rc, out, err = gssh(port, "127.0.0.1", "cat 1>&2", stdin=b"to stderr")
                check(f"goose-ssh -> {name}, stderr", rc == 0 and err.endswith(b"to stderr"), (rc, out, err))
        for h in ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"):
            rc, out, err = gssh(p_openssh, "-o", f"HostKeyAlgorithms={h}", "127.0.0.1", "echo ok")
            check(f"goose-ssh -> OpenSSH sshd, host key {h}", rc == 0 and out == b"ok\n", (rc, out, err))
        # known_hosts.
        empty = k("kh_empty")
        open(empty, "w").close()
        rc, out, err = gssh(p_goose, "127.0.0.1", "echo ok", kh=empty)
        check("unknown host refused (StrictHostKeyChecking=yes)", rc == 255 and b"host key unknown" in err, (rc, err))
        rc, out, err = run([k("goose-ssh"), "-p", str(p_goose), "-i", k("user_ed25519"), "-o",
                            f"UserKnownHostsFile={empty}", "-o", "StrictHostKeyChecking=accept-new", "127.0.0.1", "echo ok"])
        added = open(empty).read()
        check("accept-new adds the host", rc == 0 and out == b"ok\n" and pub("host_ed25519") in added, (rc, err, added))
        rc, out, err = gssh(p_goose, "127.0.0.1", "echo ok", kh=empty)
        check("then it is known", rc == 0 and out == b"ok\n", (rc, err))
        changed = k("kh_changed")
        with open(changed, "w") as f:
            f.write(f"[127.0.0.1]:{p_goose} {pub('other_ed25519')}\n")
        rc, out, err = gssh(p_goose, "127.0.0.1", "echo ok", kh=changed)
        check("changed host key refused", rc == 255 and b"host key changed" in err, (rc, err))
        rc, out, err = gssh(p_goose, "127.0.0.1", "echo ok", key="other_ed25519")
        check("a key the server does not take", rc == 255, (rc, err))

        # OpenSSH ssh to goose-sshd.
        def ossh(*args, stdin=b"", env=None):
            cmd = ["ssh", "-p", str(p_goose), "-o", f"UserKnownHostsFile={k('known_hosts')}", "-o", "BatchMode=yes",
                   "-o", "IdentitiesOnly=yes", *args]
            return run(cmd, stdin, env)

        for kex in KEXES:
            rc, out, err = ossh("-i", k("user_ed25519"), "-o", f"KexAlgorithms={kex}", "127.0.0.1", "echo ok; exit 3")
            check(f"OpenSSH ssh -> goose-sshd, {kex}", rc == 3 and out == b"ok\n", (rc, out, err))
        for c in AEADS:
            rc, out, err = ossh("-i", k("user_rsa"), "-o", f"Ciphers={c}", "127.0.0.1", "echo ok")
            check(f"OpenSSH ssh -> goose-sshd, {c}, RSA key", rc == 0 and out == b"ok\n", (rc, out, err))
        for c in CTRS:
            for m in MACS:
                rc, out, err = ossh("-i", k("user_ed25519"), "-o", f"Ciphers={c}", "-o", f"MACs={m}", "127.0.0.1", "echo ok")
                check(f"OpenSSH ssh -> goose-sshd, {c} {m}", rc == 0 and out == b"ok\n", (rc, out, err))
        env = {**os.environ, "SSH_ASKPASS": k("askpass"), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "x"}
        for method in ("password", "keyboard-interactive"):
            rc, out, err = run(["ssh", "-p", str(p_goose), "-o", f"UserKnownHostsFile={k('known_hosts')}", "-o",
                                "PubkeyAuthentication=no", "-o", f"PreferredAuthentications={method}", "127.0.0.1",
                                "echo ok"], b"", env)
            check(f"OpenSSH ssh -> goose-sshd, {method}", rc == 0 and out == b"ok\n", (rc, out, err))
        rc, out, err = ossh("-i", k("user_ed25519"), "-tt", "127.0.0.1", "tty")
        check("OpenSSH ssh -> goose-sshd, pty", rc == 0 and out.startswith(b"/dev/"), (rc, out, err))
        rc, out, err = ossh("-i", k("user_ed25519"), "127.0.0.1", "cat", stdin=big)
        check("OpenSSH ssh -> goose-sshd, 5 MB through cat", rc == 0 and hashlib.sha256(out).hexdigest() == digest,
              (rc, len(out), err))

        # Go's client to goose-sshd.
        hk = f"{pub('host_ed25519')}"
        for kex in KEXES:
            rc, out, err = run([k("gossh"), "client", str(p_goose), USER, k("user_ed25519"), hk, "echo ok; exit 2"],
                               env={**GO_ENV, "GOSSH_KEX": kex})
            check(f"Go client -> goose-sshd, {kex}", out == b"ok\nexit=2\n", (rc, out, err))
        for c in AEADS + CTRS:
            rc, out, err = run([k("gossh"), "client", str(p_goose), USER, k("user_rsa"), hk, "echo ok"],
                               env={**GO_ENV, "GOSSH_CIPHERS": c})
            check(f"Go client -> goose-sshd, {c}, RSA key", out == b"ok\nexit=0\n", (rc, out, err))
        rc, out, err = run([k("gossh"), "client", str(p_goose), USER, "-", hk, "echo ok", "letmein"])
        check("Go client -> goose-sshd, password", out == b"ok\nexit=0\n", (rc, out, err))

        # Passphrase-protected keys.
        key_env = {**os.environ, "SSH_ASKPASS": k("askpass_key"), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "x"}
        for port, name in ((p_openssh, "OpenSSH sshd"), (p_goose, "goose-sshd")):
            rc, out, err = gssh(port, "127.0.0.1", "echo ok", key="enc_goose", env=key_env)
            check(f"goose-ssh -> {name}, goose-ssh-keygen's protected key", rc == 0 and out == b"ok\n", (rc, out, err))
        for key, what in (("enc_chacha", "chacha20-poly1305"), ("enc_gcm", "aes256-gcm")):
            rc, out, err = gssh(p_goose, "127.0.0.1", "echo ok", key=key, env=key_env)
            check(f"goose-ssh -> goose-sshd, ssh-keygen's {what} protected key", rc == 0 and out == b"ok\n", (rc, out, err))
        rc, out, err = gssh(p_openssh, "127.0.0.1", "echo ok", key="enc_goose", env=env)
        check("goose-ssh -> OpenSSH sshd, a wrong passphrase refused", rc == 255 and b"bad passphrase" in err, (rc, out, err))
        rc, out, err = run(["ssh", "-p", str(p_goose), "-o", f"UserKnownHostsFile={k('known_hosts')}", "-o",
                            "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey", "-i", k("enc_goose"),
                            "127.0.0.1", "echo ok"], b"", key_env)
        check("OpenSSH ssh -> goose-sshd, goose-ssh-keygen's protected key", rc == 0 and out == b"ok\n", (rc, out, err))
        for i, cipher in enumerate(KEY_FILE_CIPHERS):
            kt = ["ed25519", "ecdsa", "rsa"][i % 3]
            path = k(f"kf_{i}")
            subprocess.run([k("goose-ssh-keygen"), "-t", kt, "-b", "2048" if kt == "rsa" else "256", "-N", PASSPHRASE,
                            "-Z", cipher, "-a", "4", "-f", path], check=True, capture_output=True)
            mine = " ".join(open(path + ".pub").read().split()[:2])
            rc, out, err = run(["ssh-keygen", "-y", "-P", PASSPHRASE, "-f", path])
            check(f"ssh-keygen reads goose-ssh-keygen's {kt} key under {cipher}",
                  rc == 0 and " ".join(out.decode().split()[:2]) == mine, (rc, out, err))
            if cipher in ("aes256-ctr", "aes256-cbc"):
                rc, out, err = run([k("gossh"), "pub", path, PASSPHRASE])
                check(f"Go reads goose-ssh-keygen's {kt} key under {cipher}",
                      rc == 0 and " ".join(out.decode().split()[:2]) == mine, (rc, out, err))
            for e in ("sha256", "md5"):
                _, ours, _ = run([k("goose-ssh-keygen"), "-l", "-E", e, "-f", path])
                _, theirs, _ = run(["ssh-keygen", "-l", "-E", e, "-f", path + ".pub"])
                check(f"goose-ssh-keygen -l -E {e}, {kt}", ours.split()[:2] == theirs.split()[:2] and ours != b"",
                      (ours, theirs))

        # Port forwarding: a file over HTTP through each kind of forward.
        os.makedirs(k("www"))
        page = os.urandom(1_000_000)
        with open(k("www/file.bin"), "wb") as f:
            f.write(page)
        page_digest = hashlib.sha256(page).hexdigest()
        p_http = free_port()
        servers.append(subprocess.Popen([sys.executable, "-m", "http.server", str(p_http), "--bind", "127.0.0.1",
                                         "--directory", k("www")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        if not wait_port(p_http):
            sys.exit("the HTTP server did not start")

        def fetch(port, socks=None):
            cmd = ["curl", "-s", "--max-time", "30", "-o", "-"]
            url = f"http://127.0.0.1:{port}/file.bin"
            if socks:
                cmd += ["--socks5-hostname", f"127.0.0.1:{socks}"]
                url = f"http://127.0.0.1:{p_http}/file.bin"
            rc, out, err = run([*cmd, url], timeout=60)
            return out

        def forward_case(name, cmd, listen, socks=False, allocated=False):
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            port = listen
            if allocated:
                # "Allocated port N for remote forward to ..." on stderr.
                port = None
                end = time.time() + 15
                buf = b""
                while time.time() < end and port is None:
                    r, _, _ = select.select([proc.stderr], [], [], 1)
                    if r:
                        buf += os.read(proc.stderr.fileno(), 4096)
                        for line in buf.split(b"\n"):
                            if line.startswith(b"Allocated port "):
                                port = int(line.split()[2])
            ok = port is not None and wait_port(port, 15)
            bodies = [fetch(port, port if socks else None) for _ in range(2)] if ok else []
            proc.kill()
            err = proc.stderr.read()[-300:] if proc.stderr else b""
            good = ok and all(hashlib.sha256(b).hexdigest() == page_digest for b in bodies)
            check(name, good, (port, [len(b) for b in bodies], err))

        for port, name in ((p_openssh, "OpenSSH sshd"), (p_goose, "goose-sshd"), (p_go, "Go")):
            base = [k("goose-ssh"), "-N", "-p", str(port), "-i", k("user_ed25519"), "-o",
                    f"UserKnownHostsFile={k('known_hosts')}", "-o", "StrictHostKeyChecking=yes"]
            lp = free_port()
            forward_case(f"goose-ssh -L through {name}", [*base, "-L", f"{lp}:127.0.0.1:{p_http}", "127.0.0.1"], lp)
            dp = free_port()
            forward_case(f"goose-ssh -D (SOCKS5) through {name}", [*base, "-D", str(dp), "127.0.0.1"], dp, socks=True)
            if port != p_go:
                rp = free_port()
                forward_case(f"goose-ssh -R through {name}", [*base, "-R", f"{rp}:127.0.0.1:{p_http}", "127.0.0.1"], rp)
        obase = ["ssh", "-N", "-p", str(p_goose), "-i", k("user_ed25519"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                 "-o", f"UserKnownHostsFile={k('known_hosts')}", "-o", "ExitOnForwardFailure=yes"]
        lp = free_port()
        forward_case("OpenSSH ssh -L through goose-sshd", [*obase, "-L", f"{lp}:127.0.0.1:{p_http}", "127.0.0.1"], lp)
        dp = free_port()
        forward_case("OpenSSH ssh -D through goose-sshd", [*obase, "-D", str(dp), "127.0.0.1"], dp, socks=True)
        rp = free_port()
        forward_case("OpenSSH ssh -R through goose-sshd", [*obase, "-R", f"{rp}:127.0.0.1:{p_http}", "127.0.0.1"], rp)
        forward_case("OpenSSH ssh -R port 0 through goose-sshd", [*obase, "-R", f"0:127.0.0.1:{p_http}", "127.0.0.1"], None,
                     allocated=True)
        rc, out, err = run([k("gossh"), "dial", str(p_goose), USER, k("user_ed25519"), hk, f"127.0.0.1:{p_http}", "/file.bin"])
        check("Go client direct-tcpip through goose-sshd", out == f"{len(page)} {page_digest}\n".encode(), (rc, out, err))

        sftp_cases(k, sftp_server, {p_goose: "goose-sshd", p_openssh: "OpenSSH sshd + sftp-server",
                                    p_osftp: "OpenSSH sshd + goose-sftp-server"})
    finally:
        for s in servers:
            s.kill()
        shutil.rmtree(t, ignore_errors=True)
    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
    sys.exit(0 if all(results) else 1)


# --- SFTP ------------------------------------------------------------------------

SFTP_BATCH = """cd {srv}
put {loc}/big
put {loc}/small
put {loc}/empty
-put {loc}/nosuch
mkdir d1
-mkdir d1
rename small d1/small2
-rename empty d1/small2
ln -s big biglink
ln big bighard
chmod 600 big
ls -l
ls -la d1
ls -n
get big {loc}/back/big
get d1/small2 {loc}/back/small
-get nosuch {loc}/back/nosuch
put -r {loc}/tree
get -r tree {loc}/back/tree
!head -c 100000 {loc}/big > {loc}/half
put {loc}/half big2
reput {loc}/big big2
get big2 {loc}/back/big2
!head -c 5000 {loc}/big > {loc}/back/big3
reget big {loc}/back/big3
rm big2
-cd nosuch
-rmdir tree
-rm nosuch
mkdir ro
chmod 500 ro
-put {loc}/small ro/x
chmod 700 ro
rmdir ro
rm biglink
rm bighard
-rename big d1/small2
ls -l d1
symlink d1 dlink
ls -l
pwd
df
"""


def sftp_batch(server, d):
    """The batch through `sftp -D server` in d: its exit status, transcript
    (d as "D", times and directories' sizes left out) and the tree left."""
    srv, loc = os.path.join(d, "srv"), os.path.join(d, "loc")
    os.makedirs(srv)
    os.makedirs(os.path.join(loc, "back"))
    os.makedirs(os.path.join(loc, "tree", "sub"))
    with open(os.path.join(loc, "big"), "wb") as f:
        f.write(bytes(range(256)) * 12000)
    with open(os.path.join(loc, "small"), "w") as f:
        f.write("hello\n")
    open(os.path.join(loc, "empty"), "w").close()
    with open(os.path.join(loc, "tree", "a"), "w") as f:
        f.write("a\n")
    with open(os.path.join(loc, "tree", "sub", "b"), "w") as f:
        f.write("b\n")
    os.chmod(os.path.join(loc, "tree", "a"), 0o640)
    batch = os.path.join(d, "..", os.path.basename(d) + ".batch")
    with open(batch, "w") as f:
        f.write(SFTP_BATCH.format(srv=srv, loc=loc))
    p = subprocess.run(["sftp", "-D", server, "-b", batch], capture_output=True, text=True, timeout=120)
    lines = []
    for l in (p.stdout + p.stderr).replace(d, "D").splitlines():
        w = l.split()
        if len(w) >= 9 and len(w[0]) == 10 and w[0][0] in "-dl":
            if w[0][0] == "d":
                w[4] = "DIRSIZE"
            w[5:8] = ["TIME"]
            l = " ".join(w)
        elif w and l.startswith(" ") and all(x.rstrip("%").isdigit() for x in w):
            l = "DF"                                   # df's numbers move as the file system does
        lines.append(l)
    tree = set()
    for root, dirs, files in os.walk(d):
        for n in dirs + files:
            pth = os.path.join(root, n)
            st = os.lstat(pth)
            if stat.S_ISREG(st.st_mode):
                body = hashlib.sha256(open(pth, "rb").read()).hexdigest()
            else:
                body = os.readlink(pth) if stat.S_ISLNK(st.st_mode) else ""
            tree.add((os.path.relpath(pth, d), oct(st.st_mode), 0 if stat.S_ISDIR(st.st_mode) else st.st_nlink, body))
    return p.returncode, lines, tree


def sftp_cases(k, sftp_server, servers):
    # The raw requests, compared reply by reply.
    rc, out, err = run([sys.executable, os.path.join(ROOT, "scripts", "sftp_raw.py"), k("goose-sftp-server"), sftp_server],
                       timeout=300)
    for line in out.decode().splitlines():
        if line.startswith(("ok    ", "FAIL  ")):
            check("sftp raw: " + line[6:].split("  ")[0], line.startswith("ok"), line[6:])
    check("sftp raw: the script ran", rc in (0, 1) and b"passed" in out, err.decode()[-500:])

    # One sftp batch through each server.
    base = os.path.join(k("sftp_batch"))
    os.makedirs(base)
    a = sftp_batch(sftp_server, os.path.join(base, "openssh"))
    b = sftp_batch(k("goose-sftp-server"), os.path.join(base, "goose"))
    check("sftp -D batch: both run to the end", a[0] == 0 and b[0] == 0, (a[0], b[0], b[1][-5:]))
    check("sftp -D batch: the same transcript", a[1] == b[1],
          [x for x in __import__("difflib").unified_diff(a[1], b[1], lineterm="", n=0)][:20])
    check("sftp -D batch: the same files left", a[2] == b[2], (sorted(a[2] - b[2])[:5], sorted(b[2] - a[2])[:5]))

    # goose-scp, and OpenSSH's scp and sftp, to each server.
    f5m = k("f5m")
    with open(f5m, "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))
    with open(k("small1"), "w") as f:
        f.write("hi\n")
    tree = k("tree")
    os.makedirs(os.path.join(tree, "sub", "deeper"))
    for rel, body, mode in (("a", "a\n", 0o640), ("sub/b", "b" * 70000, 0o600), ("sub/deeper/c", "", 0o755)):
        with open(os.path.join(tree, rel), "w") as f:
            f.write(body)
        os.chmod(os.path.join(tree, rel), mode)
    os.utime(os.path.join(tree, "sub", "b"), (1500000000, 1577934240))
    home = os.path.expanduser("~")

    def same_tree(x, y, times=False):
        for root, dirs, files in os.walk(x):
            for n in files:
                p = os.path.join(root, n)
                q = os.path.join(y, os.path.relpath(p, x))
                if not os.path.isfile(q) or open(p, "rb").read() != open(q, "rb").read():
                    return False
                if times and (int(os.stat(p).st_mtime) != int(os.stat(q).st_mtime) or
                              stat.S_IMODE(os.stat(p).st_mode) != stat.S_IMODE(os.stat(q).st_mode)):
                    return False
        return True

    def same(p, q):
        return os.path.isfile(q) and open(p, "rb").read() == open(q, "rb").read()

    for port, name in servers.items():
        g = [k("goose-scp"), "-P", str(port), "-i", k("user_ed25519"), "-o", f"UserKnownHostsFile={k('known_hosts')}",
             "-o", "StrictHostKeyChecking=yes"]
        w = k(f"scp_{port}")
        dl = os.path.join(w, "dl")
        os.makedirs(dl)
        r = lambda *a: run([*g, *a], timeout=120)
        rc, _, err = r(f5m, f"127.0.0.1:{w}/up")
        check(f"goose-scp to {name}: 5 MB up", rc == 0 and same(f5m, f"{w}/up"), (rc, err))
        rc, _, err = r(f"127.0.0.1:{w}/up", f"{dl}/back")
        check(f"goose-scp to {name}: 5 MB down", rc == 0 and same(f5m, f"{dl}/back"), (rc, err))
        open(f"{w}/empty0", "w").close()
        rc, _, err = r(f"{w}/empty0", f"127.0.0.1:{w}/emptyup")
        rc2, _, err2 = r(f"127.0.0.1:{w}/emptyup", f"{dl}/e")
        check(f"goose-scp to {name}: an empty file up and down", rc == 0 and rc2 == 0 and os.path.getsize(f"{dl}/e") == 0,
              (rc, rc2, err, err2))
        rc, _, err = r("-rp", tree, f"127.0.0.1:{w}/tree")
        check(f"goose-scp to {name}: -rp up, times and modes kept", rc == 0 and same_tree(tree, f"{w}/tree", True), (rc, err))
        rc, _, err = r("-rp", f"127.0.0.1:{w}/tree", dl + "/")
        check(f"goose-scp to {name}: -rp down into a directory", rc == 0 and same_tree(tree, f"{dl}/tree", True), (rc, err))
        rc, _, err = r("-r", tree, f"127.0.0.1:{w}/tree")
        check(f"goose-scp to {name}: -r onto a directory there: inside it", rc == 0 and same_tree(tree, f"{w}/tree/tree"),
              (rc, err))
        rc, _, err = r(f5m, k("small1"), f"127.0.0.1:{w}/")
        check(f"goose-scp to {name}: two sources into a directory",
              rc == 0 and same(f5m, f"{w}/f5m") and same(k("small1"), f"{w}/small1"), (rc, err))
        rc, _, err = r(f5m, k("small1"), f"127.0.0.1:{w}/up")
        check(f"goose-scp to {name}: two sources, the target no directory: refused", rc == 1 and same(f5m, f"{w}/up"),
              (rc, err))
        rc, _, err = r(f"127.0.0.1:{w}/*1", f"127.0.0.1:{w}/f5?", dl)
        check(f"goose-scp to {name}: patterns", rc == 0 and same(k("small1"), f"{dl}/small1") and same(f5m, f"{dl}/f5m"),
              (rc, err))
        rc, _, err = r(f"127.0.0.1:{w}/nosuch", dl)
        check(f"goose-scp to {name}: a missing source: status 1", rc == 1 and b"nosuch" in err, (rc, err))
        rc, _, err = r(tree, f"127.0.0.1:{w}/x")
        check(f"goose-scp to {name}: a directory without -r refused", rc == 1 and not os.path.exists(f"{w}/x"), (rc, err))
        os.makedirs(f"{w}/ro")
        os.chmod(f"{w}/ro", 0o500)
        rc, _, err = r(k("small1"), f"127.0.0.1:{w}/ro/x")
        os.chmod(f"{w}/ro", 0o700)
        check(f"goose-scp to {name}: an unwritable destination: status 1", rc == 1 and b"ermission denied" in err, (rc, err))
        rel = f"goose_scp_interop_{port}"
        rc, _, err = r(k("small1"), f"127.0.0.1:{rel}")
        check(f"goose-scp to {name}: a relative path: in the home directory", rc == 0 and same(k("small1"), f"{home}/{rel}"),
              (rc, err))
        rc, _, err = r(f"127.0.0.1:~/{rel}", f"{dl}/tilde")
        check(f"goose-scp to {name}: ~/path", rc == 0 and same(k("small1"), f"{dl}/tilde"), (rc, err))
        if os.path.exists(f"{home}/{rel}"):
            os.remove(f"{home}/{rel}")
        o = ["-o", f"UserKnownHostsFile={k('known_hosts')}", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
             "-o", "BatchMode=yes", "-i", k("user_ed25519"), "-P", str(port)]
        if name == "OpenSSH sshd + sftp-server":
            continue                         # OpenSSH's client and server together are not ours to test
        rc, _, err = run(["scp", "-q", *o, "-rp", tree, f"127.0.0.1:{w}/otree"], timeout=120)
        check(f"OpenSSH scp to {name}: -rp up", rc == 0 and same_tree(tree, f"{w}/otree", True), (rc, err))
        rc, _, err = run(["scp", "-q", *o, f"127.0.0.1:{w}/up", f"{dl}/oback"], timeout=120)
        check(f"OpenSSH scp to {name}: 5 MB down", rc == 0 and same(f5m, f"{dl}/oback"), (rc, err))
        batch = f"cd {w}\nput {f5m} sftp_up\nget sftp_up {dl}/sftp_back\nmkdir sd\nrename sftp_up sd/u\nls sd\nrm sd/u\nrmdir sd\n"
        rc, out, err = run(["sftp", *o[:-2], "-P", str(port), "-b", "-", "127.0.0.1"], stdin=batch.encode(), timeout=120)
        check(f"OpenSSH sftp to {name}: a batch", rc == 0 and same(f5m, f"{dl}/sftp_back") and b"sd/u" in out and
              not os.path.exists(f"{w}/sd"), (rc, out[-300:], err))


if __name__ == "__main__":
    main()
