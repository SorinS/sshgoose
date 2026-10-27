#!/usr/bin/env python3
"""Test vectors for ssh.keys, from ssh-keygen and Go's x/crypto/ssh.

Writes test/vectors/key_<name> (private keys: OpenSSH's format, and PEM
PKCS #1, SEC 1 and PKCS #8 forms; the EC and Ed25519 PEM ones from OpenSSL)) with key_<name>.pub, and
test/vectors/keys.txt:

    key <name> <type> <SHA256 fingerprint> <MD5 fingerprint>
    sig <name> <algorithm> <data hex> <signature blob hex>    (by Go)

ssh-keygen gives the fingerprints; scripts/gossh (Go's x/crypto/ssh)
signs. Go builds offline from the module cache.

    python3 scripts/gen_keys.py
"""

import os
import subprocess
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
VEC = os.path.join(ROOT, "test", "vectors")
GO_ENV = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOSUMDB": "off"}

# name, ssh-keygen arguments, private key format (None: OpenSSH's)
KEYS = [
    ("ed25519", ["-t", "ed25519"], None),
    ("ecdsa256", ["-t", "ecdsa", "-b", "256"], None),
    ("ecdsa384", ["-t", "ecdsa", "-b", "384"], None),
    ("ecdsa521", ["-t", "ecdsa", "-b", "521"], None),
    ("rsa2048", ["-t", "rsa", "-b", "2048"], None),
    ("rsa3072", ["-t", "rsa", "-b", "3072"], None),
    ("rsa_pem", ["-t", "rsa", "-b", "2048"], "PEM"),
    ("rsa_pkcs8", ["-t", "rsa", "-b", "2048"], "PKCS8"),
    ("ecdsa256_sec1", ["prime256v1"], "SEC1"),
    ("ecdsa384_pkcs8", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp384r1"], "OPENSSL"),
    ("ed25519_pkcs8", ["-algorithm", "ed25519"], "OPENSSL"),
]

SIG_ALGS = {"ssh-ed25519": ["ssh-ed25519"], "ecdsa-sha2-nistp256": ["ecdsa-sha2-nistp256"],
            "ecdsa-sha2-nistp384": ["ecdsa-sha2-nistp384"], "ecdsa-sha2-nistp521": ["ecdsa-sha2-nistp521"],
            "ssh-rsa": ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"]}


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def main():
    os.makedirs(VEC, exist_ok=True)
    tmp = tempfile.mkdtemp()
    gobin = os.path.join(tmp, "gossh")
    run(["go", "build", "-o", gobin, "."], cwd=os.path.join(ROOT, "scripts", "gossh"), env=GO_ENV)
    lines = []
    data = b"the data signed for ssh.keys' tests".hex()
    for name, args, fmt in KEYS:
        path = os.path.join(VEC, f"key_{name}")
        for p in (path, path + ".pub"):
            if os.path.exists(p):
                os.remove(p)
        if fmt == "SEC1":
            # ssh-keygen's EC keys in PEM and PKCS #8 (on LibreSSL) spell the
            # curve out, which Go refuses: OpenSSL writes the named curve.
            run(["openssl", "ecparam", "-name", args[0], "-genkey", "-noout", "-out", path])
            with open(path + ".pub", "w") as f:
                f.write(run(["ssh-keygen", "-y", "-f", path]).strip() + f" test {name}\n")
        elif fmt == "OPENSSL":
            # ssh-keygen (LibreSSL) cannot read an Ed25519 PKCS #8 key: Go
            # gives the public line.
            run(["openssl", "genpkey", *args, "-out", path])
            with open(path + ".pub", "w") as f:
                f.write(run([gobin, "pub", path]).strip() + f" test {name}\n")
        else:
            extra = ["-m", fmt] if fmt else []
            run(["ssh-keygen", "-q", *args, *extra, "-N", "", "-C", f"test {name}", "-f", path])
        pub = open(path + ".pub").read().strip()
        ktype = pub.split()[0]
        fp256 = run(["ssh-keygen", "-l", "-E", "sha256", "-f", path + ".pub"]).split()[1]
        fpmd5 = run(["ssh-keygen", "-l", "-E", "md5", "-f", path + ".pub"]).split()[1][len("MD5:"):]
        lines.append(f"key {name} {ktype} {fp256} {fpmd5}")
        for alg in SIG_ALGS[ktype]:
            sig = run([gobin, "sign", path, alg, data]).strip()
            lines.append(f"sig {name} {alg} {data} {sig}")
    with open(os.path.join(VEC, "keys.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{len(lines)} lines")


if __name__ == "__main__":
    main()
