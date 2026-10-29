// The operating system for tools/ssh.goose and tools/sshd.goose: the C of
// tools/net.c (sockets, polling, the terminal, child processes), declared
// for Goose, and a few helpers. Each root file's .build sidecar compiles
// net.c.
namespace sysnet;

import std;
import os;

extern fn net_init();
extern fn net_connect(host: const u8[:], port: i32) -> i32;
extern fn net_listen(addr: const u8[:], port: i32) -> i32;
extern fn net_accept(fd: i32, peer: u8[:], peer_len: i64&, peer_port: i32&) -> i32;
extern fn net_local_port(fd: i32) -> i32;
// ready[i] = 1 for each fds[i] (-1: none) readable or closed; how many, 0 on timeout.
extern fn net_poll_set(fds: const i32[:], ready: u8[:], timeout_ms: i32) -> i32;
// The same, waiting instead for fds[i] to take a write where write[i] != 0.
extern fn net_poll_rw(fds: const i32[:], write: const u8[:], ready: u8[:], timeout_ms: i32) -> i32;
extern fn net_read(fd: i32, buf: u8[:]) -> i64;
extern fn net_write(fd: i32, data: const u8[:]) -> i64;
// One write of what fits: bytes written, 0 when a non-blocking fd is full, -1 on error.
extern fn net_write_some(fd: i32, data: const u8[:]) -> i64;
extern fn net_close(fd: i32);
extern fn net_shutdown_write(fd: i32);
// Bit i set when the i-th descriptor (-1: none) is readable or closed; 0 on timeout.
extern fn net_poll(a: i32, b: i32, c: i32, d: i32, timeout_ms: i32) -> i32;

extern fn tty_is(fd: i32) -> i32;
extern fn tty_raw(fd: i32) -> i32;
extern fn tty_restore(fd: i32);
extern fn tty_cols(fd: i32) -> i32;
extern fn tty_rows(fd: i32) -> i32;
extern fn tty_secret(prompt: const u8[:], out: u8[:]) -> i64;
extern fn tty_line(prompt: const u8[:], out: u8[:]) -> i64;

// env: NAME=VALUE lines for the child. cmd "" runs the user's login shell.
// in_fd is non-blocking: write to it with net_write_some.
extern fn proc_spawn(cmd: const u8[:], env: const u8[:], in_fd: i32&, out_fd: i32&, err_fd: i32&) -> i32;
extern fn proc_spawn_pty(cmd: const u8[:], env: const u8[:], term: const u8[:], cols: i32, rows: i32, master: i32&) -> i32;
extern fn proc_resize(master: i32, cols: i32, rows: i32);
extern fn proc_wait(pid: i32, wait: i32) -> i32;
extern fn proc_kill(pid: i32, sig: i32);
extern fn proc_fork() -> i32;
extern fn proc_reap();
extern fn proc_exit(code: i32);

extern fn os_user(out: u8[:]) -> i64;
extern fn os_home(out: u8[:]) -> i64;
extern fn os_chmod(path: const u8[:], mode: i32) -> i32;

// Reads what is there (up to 64 KB) into a builder: how many bytes, 0 at
// end of file, -1 on error.
fn read_some(fd: i32, out: u8[>..]&) -> i64 {
    var buf: u8[65536] = [0; 65536];
    let n = net_read(fd, buf);
    if n > 0 { out.append(buf[..n]); }
    return n;
}

fn user_name() -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = os_user(buf);
    var out: u8[>..] = [];
    out.append(buf[..n]);
    return out;
}

fn home_dir() -> u8[>..] {
    var buf: u8[1024] = [0; 1024];
    let n = os_home(buf);
    var out: u8[>..] = [];
    out.append(buf[..n]);
    return out;
}

fn secret(prompt: const u8[:]) -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = tty_secret(prompt, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); }
    return out;
}

fn ask_line(prompt: const u8[:]) -> u8[>..] {
    var buf: u8[256] = [0; 256];
    let n = tty_line(prompt, buf);
    var out: u8[>..] = [];
    if n > 0 { out.append(buf[..n]); }
    return out;
}

fn eprint(s: const u8[:]) { write_stderr(s); }
