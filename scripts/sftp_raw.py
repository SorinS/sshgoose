#!/usr/bin/env python3
"""SFTP version 3 requests sent byte by byte to an SFTP server on its stdin and
stdout, as clients do not send them: the same requests to OpenSSH's
sftp-server and to goose-sftp-server, each in a directory of its own, and their
replies compared (types, status codes and messages, data, sizes and modes).
Then what only goose-sftp-server is asked, since OpenSSH's ends the session on
any request it cannot parse: an unknown packet type, a path holding a NUL, a request missing its
fields, a path too long, the handle limit, a packet too long, a request before
INIT.

    python3 scripts/sftp_raw.py GOOSE_SFTP_SERVER OPENSSH_SFTP_SERVER

Each line it prints is a check, "ok" or "FAIL"; it exits 1 if any failed.
interop.py runs it."""

import os
import shutil
import struct
import subprocess
import sys
import tempfile

FXP = dict(INIT=1, VERSION=2, OPEN=3, CLOSE=4, READ=5, WRITE=6, LSTAT=7, FSTAT=8, SETSTAT=9, FSETSTAT=10,
           OPENDIR=11, READDIR=12, REMOVE=13, MKDIR=14, RMDIR=15, REALPATH=16, STAT=17, RENAME=18, READLINK=19,
           SYMLINK=20, STATUS=101, HANDLE=102, DATA=103, NAME=104, ATTRS=105, EXTENDED=200, EXTENDED_REPLY=201)
NAMES = {v: k for k, v in FXP.items()}
READ, WRITE, APPEND, CREAT, TRUNC, EXCL = 1, 2, 4, 8, 16, 32

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("ok    " if ok else "FAIL  ") + name + ("" if ok else "  " + str(detail)))


def u32(v): return struct.pack(">I", v)
def u64(v): return struct.pack(">Q", v)
def s(b): return u32(len(b)) + (b.encode() if isinstance(b, str) else b)


def attrs(size=None, perm=None, times=None):
    flags, body = 0, b""
    if size is not None: flags |= 1; body += u64(size)
    if perm is not None: flags |= 4; body += u32(perm)
    if times is not None: flags |= 8; body += u32(times[0]) + u32(times[1])
    return u32(flags) + body


class Reader:
    def __init__(self, b): self.b, self.p = b, 0
    def u32(self): v = struct.unpack(">I", self.b[self.p:self.p + 4])[0]; self.p += 4; return v
    def u64(self): v = struct.unpack(">Q", self.b[self.p:self.p + 8])[0]; self.p += 8; return v
    def s(self): n = self.u32(); v = self.b[self.p:self.p + n]; self.p += n; return v
    def attrs(self):
        f = self.u32(); a = {}
        if f & 1: a["size"] = self.u64()
        if f & 2: a["uid"] = self.u32(); a["gid"] = self.u32()
        if f & 4: a["perm"] = self.u32()
        if f & 8: a["atime"] = self.u32(); a["mtime"] = self.u32()
        if f & 0x80000000:
            for _ in range(self.u32()): self.s(); self.s()
        return a


class Server:
    """A server process, in its own working directory."""
    def __init__(self, path, cwd):
        self.p = subprocess.Popen([path], cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
        self.id = 0

    def send_raw(self, b):
        self.p.stdin.write(b); self.p.stdin.flush()

    def recv(self):
        h = self.p.stdout.read(4)
        if len(h) < 4: return None
        n = struct.unpack(">I", h)[0]
        return self.p.stdout.read(n)

    def req(self, kind, body):
        self.id += 1
        self.send_raw(u32(5 + len(body)) + bytes([FXP[kind]]) + u32(self.id) + body)
        return self.recv()

    def close(self):
        try: self.p.stdin.close()
        except Exception: pass
        try: return self.p.wait(timeout=10)
        except subprocess.TimeoutExpired: self.p.kill(); return None


def summary(reply, root):
    """A reply as what both servers must agree on: its type, then its fields,
    a handle as "H", a path's directory as "ROOT"; attributes as size and
    mode (owner and times differ); extended replies by their u64 count."""
    if reply is None: return ("gone",)
    t = reply[0]; r = Reader(reply[5:])
    name = NAMES.get(t, t)
    if name == "STATUS":
        code = r.u32(); msg = r.s().decode()
        return ("STATUS", code, msg)
    if name == "HANDLE": return ("HANDLE",)
    if name == "DATA": return ("DATA", r.s())
    if name == "ATTRS": a = r.attrs(); return ("ATTRS", a.get("size"), a.get("perm"))
    if name == "NAME":
        n = r.u32(); out = []
        for _ in range(n):
            f = r.s().decode().replace(root, "ROOT"); r.s(); a = r.attrs()
            out.append((f, a.get("perm")))
        return ("NAME", tuple(sorted(out)))
    if name == "EXTENDED_REPLY": return ("EXTENDED_REPLY", len(reply) - 5)
    return (name,)


def handle_of(reply):
    if reply is None or reply[0] != FXP["HANDLE"]: return b"\x00" * 8
    return Reader(reply[5:]).s()


def init(srv):
    srv.send_raw(u32(5) + bytes([FXP["INIT"]]) + u32(3))
    v = srv.recv()
    r = Reader(v[5:]); exts = {}
    while r.p < len(r.b):
        k = r.s().decode(); exts[k] = r.s().decode()
    return v[0], struct.unpack(">I", v[1:5])[0], exts


def script(srv, root, home):
    """The requests both servers get: (label, summary) pairs."""
    out = []
    def q(label, kind, body): out.append((label, summary(srv.req(kind, body), root))); return out[-1][1]
    def qh(label, kind, body):
        rep = srv.req(kind, body); out.append((label, summary(rep, root))); return handle_of(rep)

    q("open a missing file", "OPEN", s("nosuch") + u32(READ) + attrs())
    h = qh("open a new file, EXCL", "OPEN", s("f") + u32(WRITE | CREAT | EXCL) + attrs(perm=0o600))
    q("write at 0", "WRITE", s(h) + u64(0) + s(b"hello"))
    q("write past the end", "WRITE", s(h) + u64(10) + s(b"XY"))
    q("fstat: the size with the hole", "FSTAT", s(h))
    q("read from a handle opened to write", "READ", s(h) + u64(0) + u32(10))
    q("close", "CLOSE", s(h))
    q("close again: a stale handle", "CLOSE", s(h))
    q("write to a stale handle", "WRITE", s(h) + u64(0) + s(b"x"))
    q("open with EXCL, the file there", "OPEN", s("f") + u32(WRITE | CREAT | EXCL) + attrs())
    h = qh("open to append", "OPEN", s("f") + u32(WRITE | APPEND) + attrs())
    q("write to an append handle at 0: at the end", "WRITE", s(h) + u64(0) + s(b"Z"))
    q("close", "CLOSE", s(h))
    h = qh("open to read", "OPEN", s("f") + u32(READ) + attrs())
    q("read it all", "READ", s(h) + u64(0) + u32(100))
    q("read at its end", "READ", s(h) + u64(13) + u32(100))
    q("read far past its end", "READ", s(h) + u64(1 << 40) + u32(100))
    q("read with a write to it", "WRITE", s(h) + u64(0) + s(b"x"))
    q("readdir on a file handle", "READDIR", s(h))
    q("close", "CLOSE", s(h))
    q("a handle never given", "FSTAT", s(b"\x00\x00\x00\x05\x00\x00\x00\x09"))
    q("a handle of the wrong length", "CLOSE", s(b"xyz"))
    # Large reads are cut to what the server sends at most.
    with open(os.path.join(root, "big"), "wb") as f: f.write(bytes(range(256)) * 2000)
    h = qh("open a 512000-byte file", "OPEN", s("big") + u32(READ) + attrs())
    rep = srv.req("READ", s(h) + u64(0) + u32(400000))
    out.append(("a READ of 400000 bytes, cut", ("DATA", len(Reader(rep[5:]).s()) if rep and rep[0] == FXP["DATA"] else rep)))
    q("close", "CLOSE", s(h))
    # Links.
    q("symlink l -> f (the target first)", "SYMLINK", s("f") + s("l"))
    q("lstat l: a link", "LSTAT", s("l"))
    q("stat l: the file", "STAT", s("l"))
    q("readlink l", "READLINK", s("l"))
    q("readlink a file", "READLINK", s("f"))
    # Renames: RENAME refuses to replace, posix-rename does.
    with open(os.path.join(root, "h"), "w") as f: f.write("h")
    q("rename f -> g", "RENAME", s("f") + s("g"))
    q("rename g -> h, which is there", "RENAME", s("g") + s("h"))
    q("stat g, still there", "STAT", s("g"))
    q("posix-rename g -> h", "EXTENDED", s("posix-rename@openssh.com") + s("g") + s("h"))
    q("stat h: g's size", "STAT", s("h"))
    q("rename a missing file", "RENAME", s("nosuch") + s("x"))
    # Directories.
    q("mkdir d 0700", "MKDIR", s("d") + attrs(perm=0o700))
    q("mkdir d again", "MKDIR", s("d") + attrs())
    with open(os.path.join(root, "d", "in"), "w") as f: f.write("in")
    q("rmdir d, not empty", "RMDIR", s("d"))
    q("remove a directory", "REMOVE", s("d"))
    h = qh("opendir d", "OPENDIR", s("d"))
    names = set()
    for _ in range(10):
        rep = srv.req("READDIR", s(h))
        if rep is None or rep[0] != FXP["NAME"]: out.append(("readdir to its end", summary(rep, root))); break
        r = Reader(rep[5:])
        for _ in range(r.u32()): names.add(r.s().decode()); r.s(); r.attrs()
    out.append(("readdir's names", tuple(sorted(names))))
    q("readdir after the end", "READDIR", s(h))
    q("close the directory", "CLOSE", s(h))
    q("opendir a file", "OPENDIR", s("h"))
    q("opendir a missing one", "OPENDIR", s("nosuch"))
    q("remove a missing file", "REMOVE", s("nosuch"))
    q("rmdir a missing one", "RMDIR", s("nosuch"))
    # Paths.
    q("realpath .", "REALPATH", s("."))
    q("realpath of nothing", "REALPATH", s(""))
    q("realpath d/../h", "REALPATH", s("d/../h"))
    q("realpath of a missing last part", "REALPATH", s("newfile"))
    q("realpath of a missing directory", "REALPATH", s("nosuch/x"))
    q("stat a missing file", "STAT", s("nosuch"))
    q("stat a path through a file", "STAT", s("h/x"))
    # Attributes.
    q("setstat: size 1", "SETSTAT", s("h") + attrs(size=1))
    q("setstat: mode 0640", "SETSTAT", s("h") + attrs(perm=0o640))
    q("setstat: times", "SETSTAT", s("h") + attrs(times=(1000000000, 1000000001)))
    q("stat h", "STAT", s("h"))
    q("setstat a missing file", "SETSTAT", s("nosuch") + attrs(perm=0o600))
    h = qh("open h to write", "OPEN", s("h") + u32(WRITE) + attrs())
    q("fsetstat: size 5", "FSETSTAT", s(h) + attrs(size=5))
    q("fsetstat: mode 0600", "FSETSTAT", s(h) + attrs(perm=0o600))
    q("fsync", "EXTENDED", s("fsync@openssh.com") + s(h))
    q("fstatvfs", "EXTENDED", s("fstatvfs@openssh.com") + s(h))
    q("close", "CLOSE", s(h))
    q("stat h after fsetstat", "STAT", s("h"))
    q("lsetstat l: times on the link", "EXTENDED", s("lsetstat@openssh.com") + s("l") + attrs(times=(1, 2)))
    # The other extensions.
    q("statvfs .", "EXTENDED", s("statvfs@openssh.com") + s("."))
    q("hardlink h -> hh", "EXTENDED", s("hardlink@openssh.com") + s("h") + s("hh"))
    q("hardlink onto a file there", "EXTENDED", s("hardlink@openssh.com") + s("h") + s("hh"))
    q("limits", "EXTENDED", s("limits@openssh.com"))
    for p in ("~", "~/x", "~root/x", "~nosuchuser9", "rel"):
        rep = srv.req("EXTENDED", s("expand-path@openssh.com") + s(p))
        out.append((f"expand-path {p}", Reader(rep[9:]).s().decode().replace(root, "ROOT") if rep and rep[0] == FXP["NAME"]
                     else summary(rep, root)))
    rep = srv.req("EXTENDED", s("home-directory") + s(""))
    out.append(("home-directory of no one: ours", summary(rep, root)[0]))
    rep = srv.req("EXTENDED", s("users-groups-by-id@openssh.com") + s(u32(os.getuid())) + s(u32(os.getgid())))
    if rep and rep[0] == FXP["EXTENDED_REPLY"]:
        r = Reader(rep[5:]); users = Reader(r.s()); groups = Reader(r.s())
        out.append(("users-groups-by-id", (users.s().decode(), groups.s().decode())))
    else:
        out.append(("users-groups-by-id", summary(rep, root)))
    h1 = qh("open big to read", "OPEN", s("big") + u32(READ) + attrs())
    h2 = qh("open c to write", "OPEN", s("c") + u32(WRITE | CREAT | TRUNC) + attrs(perm=0o644))
    q("copy-data: 1000 bytes from 7 to 3", "EXTENDED", s("copy-data") + s(h1) + u64(7) + u64(1000) + s(h2) + u64(3))
    q("copy-data: past the end", "EXTENDED", s("copy-data") + s(h1) + u64(511000) + u64(5000) + s(h2) + u64(0))
    q("close", "CLOSE", s(h1))
    q("close", "CLOSE", s(h2))
    q("stat c", "STAT", s("c"))
    q("an extension no one has", "EXTENDED", s("nosuch@example.com"))
    return out


def main():
    goose, openssh = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    home = os.path.realpath(os.path.expanduser("~"))
    base = tempfile.mkdtemp()
    try:
        runs = {}
        versions = {}
        for name, path in (("openssh", openssh), ("goose", goose)):
            root = os.path.realpath(os.path.join(base, name))
            os.mkdir(root)
            srv = Server(path, root)
            versions[name] = init(srv)
            runs[name] = script(srv, root, home)
            # Both files the same.
            runs[name].append(("c's bytes", open(os.path.join(root, "c"), "rb").read()))
            runs[name].append(("hh, a link to h", os.stat(os.path.join(root, "hh")).st_ino == os.stat(os.path.join(root, "h")).st_ino))
            runs[name].append(("exit at stdin's end", srv.close()))
        gv, ov = versions["goose"], versions["openssh"]
        check("VERSION 3", gv[0] == FXP["VERSION"] and gv[1] == 3, gv[:2])
        missing = [k for k in gv[2] if k not in ov[2]]
        check("goose's extensions are OpenSSH's, at the same versions",
              not missing and all(ov[2][k] == v for k, v in gv[2].items()), (missing, gv[2]))
        for (label, a), (_, b) in zip(runs["openssh"], runs["goose"]):
            check(label, a == b, f"openssh {a!r}, goose {b!r}")
        check("the same number of requests", len(runs["openssh"]) == len(runs["goose"]))

        # What only goose-sftp-server is asked (OpenSSH's ends the session
        # on the first, as its string parser refuses a NUL).
        root = os.path.realpath(os.path.join(base, "goose2"))
        os.mkdir(root)
        srv = Server(goose, root)
        init(srv)
        rep = summary(srv.req("OPEN", s(b"a\x00b") + u32(WRITE | CREAT) + attrs()), root)
        check("a path holding a NUL: a bad message", rep == ("STATUS", 5, "Bad message"), rep)
        check("nothing made for it", os.listdir(root) == [], os.listdir(root))
        # OpenSSH's logs "Unknown message" and sends nothing, which leaves a
        # client waiting; the draft (§7) has OP_UNSUPPORTED.
        srv.id += 1
        srv.send_raw(u32(5) + bytes([250]) + u32(srv.id))
        rep = summary(srv.recv(), root)
        check("an unknown packet type: unsupported", rep == ("STATUS", 8, "Operation unsupported"), rep)
        rep = summary(srv.req("SYMLINK", b""), root)
        check("a request missing its fields: a bad message", rep == ("STATUS", 5, "Bad message"), rep)
        rep = summary(srv.req("STAT", s("x" * 5000)), root)
        check("a path too long: a bad message", rep == ("STATUS", 5, "Bad message"), rep)
        handles = []
        for i in range(70):
            r = srv.req("OPENDIR", s("."))
            if r[0] != FXP["HANDLE"]: break
            handles.append(handle_of(r))
        check("64 handles at most", len(handles) == 64, len(handles))
        r = summary(srv.req("CLOSE", s(handles[5])), root)
        h = handle_of(srv.req("OPENDIR", s(".")))
        check("a closed handle's slot reused under another name", h != handles[5] and h[:4] == handles[5][:4], (h, handles[5]))
        check("the old name refused", summary(srv.req("READDIR", s(handles[5])), root)[0:2] == ("STATUS", 4))
        srv.send_raw(u32(300000) + b"\x05")
        check("a packet too long ends the session", srv.recv() is None and srv.close() == 1)
        srv = Server(goose, root)
        srv.send_raw(u32(9) + bytes([FXP["STAT"]]) + u32(1) + s("."))
        check("a request before INIT ends the session", srv.recv() is None and srv.close() == 1)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{sum(results)} passed, {len(results) - sum(results)} failed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
