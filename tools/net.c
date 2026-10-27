/* The operating system's part of tools/ssh.goose and tools/sshd.goose:
   TCP sockets, waiting on several descriptors, the terminal (raw mode,
   its size, a password read without echo), and child processes on pipes
   or a pseudo-terminal. POSIX: macOS and Linux. Each function returns -1
   (or a negative value) on failure; strings arrive as Goose slices,
   { data, len }, not NUL-terminated. */

#define _XOPEN_SOURCE 600
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

typedef struct { const uint8_t *data; int64_t len; } net_slice;
typedef struct { uint8_t *data; int64_t len; } net_buf;

/* A slice as a C string, in a buffer of the caller's. */
static int cstring(net_slice s, char *out, size_t cap) {
    if (s.len < 0 || (size_t)s.len >= cap) return -1;
    memcpy(out, s.data, (size_t)s.len);
    out[s.len] = 0;
    return 0;
}

/* --- Sockets ------------------------------------------------------------ */

int32_t net_connect(net_slice host, int32_t port) {
    char h[256], p[16];
    if (cstring(host, h, sizeof h) < 0) return -1;
    snprintf(p, sizeof p, "%d", port);
    struct addrinfo hints, *res, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hints, &res) != 0) return -2;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return fd;
}

/* Listens on addr:port ("" for every address). */
int32_t net_listen(net_slice addr, int32_t port) {
    char h[256], p[16];
    if (cstring(addr, h, sizeof h) < 0) return -1;
    snprintf(p, sizeof p, "%d", port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(h[0] ? h : NULL, p, &hints, &res) != 0) return -2;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(fd, res->ai_addr, res->ai_addrlen) < 0 || listen(fd, 16) < 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

/* A connection, and its peer's address as text into `peer`, its length
   through peer_len, and its port through peer_port. */
int32_t net_accept(int32_t fd, net_buf peer, int64_t *peer_len, int32_t *peer_port) {
    struct sockaddr_storage sa;
    socklen_t n = sizeof sa;
    int c;
    do { c = accept(fd, (struct sockaddr *)&sa, &n); } while (c < 0 && errno == EINTR);
    *peer_len = 0;
    *peer_port = 0;
    if (c < 0) return -1;
    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo((struct sockaddr *)&sa, n, host, sizeof host, serv, sizeof serv, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
        *peer_port = atoi(serv);
        size_t l = strlen(host);
        if ((int64_t)l > peer.len) l = (size_t)peer.len;
        memcpy(peer.data, host, l);
        *peer_len = (int64_t)l;
    }
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    return c;
}

/* Up to buf.len bytes: how many, 0 at end of file, -1 on error. */
int64_t net_read(int32_t fd, net_buf buf) {
    ssize_t n;
    do { n = read(fd, buf.data, (size_t)buf.len); } while (n < 0 && errno == EINTR);
    return n < 0 ? -1 : (int64_t)n;
}

/* All of data, or -1. */
int64_t net_write(int32_t fd, net_slice data) {
    int64_t off = 0;
    while (off < data.len) {
        ssize_t n = write(fd, data.data + off, (size_t)(data.len - off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += n;
    }
    return off;
}

void net_close(int32_t fd) { if (fd >= 0) close(fd); }

/* The port a socket is bound to (a listener's, after port 0). */
int32_t net_local_port(int32_t fd) {
    struct sockaddr_storage sa;
    socklen_t n = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &n) < 0) return -1;
    if (sa.ss_family == AF_INET) return ntohs(((struct sockaddr_in *)&sa)->sin_port);
    if (sa.ss_family == AF_INET6) return ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
    return -1;
}

typedef struct { const int32_t *data; int64_t len; } net_fds;

/* Waits up to timeout_ms for any descriptor of fds (-1 entries ignored, at
   most 256) to be readable or closed: ready[i] is 1 for those that are.
   How many are, 0 on timeout. */
int32_t net_poll_set(net_fds fds, net_buf ready, int32_t timeout_ms) {
    struct pollfd p[256];
    int map[256];
    int n = 0;
    for (int64_t i = 0; i < fds.len && i < ready.len && n < 256; i++) {
        ready.data[i] = 0;
        if (fds.data[i] < 0) continue;
        p[n].fd = fds.data[i];
        p[n].events = POLLIN;
        p[n].revents = 0;
        map[n++] = (int)i;
    }
    int r;
    do { r = poll(p, (nfds_t)n, timeout_ms); } while (r < 0 && errno == EINTR);
    if (r <= 0) return r;
    for (int i = 0; i < n; i++)
        if (p[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) ready.data[map[i]] = 1;
    return r;
}

void net_shutdown_write(int32_t fd) { if (fd >= 0) shutdown(fd, SHUT_WR); }

/* Waits up to timeout_ms (-1: no limit) for any of four descriptors (-1:
   none) to be readable or closed: bit i set for fd i. 0 on timeout. */
int32_t net_poll(int32_t a, int32_t b, int32_t c, int32_t d, int32_t timeout_ms) {
    struct pollfd p[4];
    int32_t fds[4] = { a, b, c, d };
    int n = 0, map[4];
    for (int i = 0; i < 4; i++) {
        if (fds[i] < 0) continue;
        p[n].fd = fds[i];
        p[n].events = POLLIN;
        p[n].revents = 0;
        map[n++] = i;
    }
    int r;
    do { r = poll(p, (nfds_t)n, timeout_ms); } while (r < 0 && errno == EINTR);
    if (r <= 0) return r;
    int32_t bits = 0;
    for (int i = 0; i < n; i++)
        /* POLLNVAL too: macOS cannot poll device files such as /dev/null, and a
           read then says what they hold. */
        if (p[i].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) bits |= 1 << map[i];
    return bits;
}

/* --- The terminal --------------------------------------------------------- */

static struct termios saved;
static int saved_ok = 0;

int32_t tty_is(int32_t fd) { return isatty(fd) ? 1 : 0; }

int32_t tty_raw(int32_t fd) {
    if (tcgetattr(fd, &saved) < 0) return -1;
    saved_ok = 1;
    struct termios t = saved;
    cfmakeraw(&t);
    return tcsetattr(fd, TCSAFLUSH, &t);
}

void tty_restore(int32_t fd) { if (saved_ok) tcsetattr(fd, TCSAFLUSH, &saved); }

int32_t tty_cols(int32_t fd) {
    struct winsize w;
    return ioctl(fd, TIOCGWINSZ, &w) == 0 && w.ws_col ? w.ws_col : 80;
}

int32_t tty_rows(int32_t fd) {
    struct winsize w;
    return ioctl(fd, TIOCGWINSZ, &w) == 0 && w.ws_row ? w.ws_row : 24;
}

/* A line typed at the terminal without echo, after a prompt: its length,
   or -1 without a terminal. */
int64_t tty_secret(net_slice prompt, net_buf out) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return -1;
    if (write(fd, prompt.data, (size_t)prompt.len) < 0) { close(fd); return -1; }
    struct termios t, quiet;
    tcgetattr(fd, &t);
    quiet = t;
    quiet.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(fd, TCSAFLUSH, &quiet);
    int64_t n = 0;
    char ch;
    while (n < out.len && read(fd, &ch, 1) == 1 && ch != '\n' && ch != '\r') out.data[n++] = (uint8_t)ch;
    tcsetattr(fd, TCSAFLUSH, &t);
    if (write(fd, "\n", 1) < 0) {}
    close(fd);
    return n;
}

/* A line typed at the terminal, echoed (for yes/no). */
int64_t tty_line(net_slice prompt, net_buf out) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return -1;
    if (write(fd, prompt.data, (size_t)prompt.len) < 0) { close(fd); return -1; }
    int64_t n = 0;
    char ch;
    while (n < out.len && read(fd, &ch, 1) == 1 && ch != '\n') out.data[n++] = (uint8_t)ch;
    close(fd);
    return n;
}

/* --- Processes -------------------------------------------------------------- */

/* The user's shell. */
static const char *user_shell(void) {
    const char *s = getenv("SHELL");
    return s && *s ? s : "/bin/sh";
}

/* Exports NAME=VALUE pairs, one per line, in the child. */
static void put_env(net_slice env) {
    char line[4096];
    int64_t i = 0;
    while (i < env.len) {
        int64_t j = i;
        while (j < env.len && env.data[j] != '\n') j++;
        if (j - i < (int64_t)sizeof line) {
            memcpy(line, env.data + i, (size_t)(j - i));
            line[j - i] = 0;
            char *eq = strchr(line, '=');
            if (eq) { *eq = 0; setenv(line, eq + 1, 1); }
        }
        i = j + 1;
    }
}

/* Runs `cmd` with the user's shell (-c), or the shell itself for "",
   on three pipes: its stdin, stdout and stderr ends through the pointers.
   The child's pid, or -1. */
int32_t proc_spawn(net_slice cmd, net_slice env, int32_t *in_fd, int32_t *out_fd, int32_t *err_fd) {
    char c[65536];
    if (cstring(cmd, c, sizeof c) < 0) return -1;
    int pin[2], pout[2], perr[2];
    if (pipe(pin) < 0) return -1;
    if (pipe(pout) < 0) { close(pin[0]); close(pin[1]); return -1; }
    if (pipe(perr) < 0) { close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]); return -1; }
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        dup2(pin[0], 0);
        dup2(pout[1], 1);
        dup2(perr[1], 2);
        close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]); close(perr[0]); close(perr[1]);
        put_env(env);
        const char *sh = user_shell();
        if (c[0]) execl(sh, sh, "-c", c, (char *)NULL);
        else execl(sh, sh, "-l", (char *)NULL);
        _exit(127);
    }
    close(pin[0]); close(pout[1]); close(perr[1]);
    *in_fd = pin[1];
    *out_fd = pout[0];
    *err_fd = perr[0];
    return pid;
}

/* The same on a new pseudo-terminal of cols x rows: the master end through
   master_fd, which carries stdin, stdout and stderr. */
int32_t proc_spawn_pty(net_slice cmd, net_slice env, net_slice term, int32_t cols, int32_t rows, int32_t *master_fd) {
    char c[65536], t[256];
    if (cstring(cmd, c, sizeof c) < 0 || cstring(term, t, sizeof t) < 0) return -1;
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || grantpt(m) < 0 || unlockpt(m) < 0) { if (m >= 0) close(m); return -1; }
    char *sname = ptsname(m);
    if (!sname) { close(m); return -1; }
    char slave[256];
    snprintf(slave, sizeof slave, "%s", sname);
    struct winsize w;
    memset(&w, 0, sizeof w);
    w.ws_col = (unsigned short)cols;
    w.ws_row = (unsigned short)rows;
    pid_t pid = fork();
    if (pid < 0) { close(m); return -1; }
    if (pid == 0) {
        setsid();
        int s = open(slave, O_RDWR);
        if (s < 0) _exit(127);
        ioctl(s, TIOCSCTTY, 0);
        ioctl(s, TIOCSWINSZ, &w);
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        if (s > 2) close(s);
        close(m);
        if (t[0]) setenv("TERM", t, 1);
        put_env(env);
        const char *sh = user_shell();
        if (c[0]) execl(sh, sh, "-c", c, (char *)NULL);
        else execl(sh, sh, "-l", (char *)NULL);
        _exit(127);
    }
    ioctl(m, TIOCSWINSZ, &w);
    *master_fd = m;
    return pid;
}

void proc_resize(int32_t master_fd, int32_t cols, int32_t rows) {
    struct winsize w;
    memset(&w, 0, sizeof w);
    w.ws_col = (unsigned short)cols;
    w.ws_row = (unsigned short)rows;
    ioctl(master_fd, TIOCSWINSZ, &w);
}

/* A child's exit status: -1 while it runs (block: wait for it); 128 plus
   the signal for one that was killed. */
int32_t proc_wait(int32_t pid, int32_t block) {
    int st;
    pid_t r;
    do { r = waitpid(pid, &st, block ? 0 : WNOHANG); } while (r < 0 && errno == EINTR);
    if (r == 0) return -1;
    if (r < 0) return 255;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 255;
}

void proc_kill(int32_t pid, int32_t sig) { if (pid > 0) kill(-pid, sig); }

/* fork(), for a server's connection: 0 in the child. Children of the
   server are reaped as they end. */
int32_t proc_fork(void) {
    signal(SIGCHLD, SIG_DFL);
    return (int32_t)fork();
}

void proc_reap(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
}

void proc_exit(int32_t code) { _exit(code); }

/* SIGPIPE off: a closed peer is a write error, not a death. */
void net_init(void) { signal(SIGPIPE, SIG_IGN); }

/* The user running this, and their home directory. */
int64_t os_user(net_buf out) {
    const char *u = getenv("USER");
    if (!u) u = getenv("LOGNAME");
    if (!u) return 0;
    size_t l = strlen(u);
    if ((int64_t)l > out.len) l = (size_t)out.len;
    memcpy(out.data, u, l);
    return (int64_t)l;
}

int64_t os_home(net_buf out) {
    const char *h = getenv("HOME");
    if (!h) return 0;
    size_t l = strlen(h);
    if ((int64_t)l > out.len) l = (size_t)out.len;
    memcpy(out.data, h, l);
    return (int64_t)l;
}
