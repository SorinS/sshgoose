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
#include <sys/stat.h>
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
   most 256) to be readable or closed, or, where write[i] is nonzero (write
   may be shorter than fds), to take a write: ready[i] is 1 for those that
   are. How many are, 0 on timeout. */
int32_t net_poll_rw(net_fds fds, net_buf write, net_buf ready, int32_t timeout_ms) {
    struct pollfd p[256];
    int map[256];
    int n = 0;
    for (int64_t i = 0; i < fds.len && i < ready.len && n < 256; i++) {
        ready.data[i] = 0;
        if (fds.data[i] < 0) continue;
        p[n].fd = fds.data[i];
        p[n].events = i < write.len && write.data[i] ? POLLOUT : POLLIN;
        p[n].revents = 0;
        map[n++] = (int)i;
    }
    int r;
    do { r = poll(p, (nfds_t)n, timeout_ms); } while (r < 0 && errno == EINTR);
    if (r <= 0) return r;
    for (int i = 0; i < n; i++)
        if (p[i].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR | POLLNVAL)) ready.data[map[i]] = 1;
    return r;
}

/* The same, for reading only. */
int32_t net_poll_set(net_fds fds, net_buf ready, int32_t timeout_ms) {
    net_buf none = { NULL, 0 };
    return net_poll_rw(fds, none, ready, timeout_ms);
}

/* One write of what fits: how many bytes went, 0 when a non-blocking fd
   is full, -1 on error (a closed reader among them). */
int64_t net_write_some(int32_t fd, net_slice data) {
    ssize_t n;
    do { n = write(fd, data.data, (size_t)data.len); } while (n < 0 && errno == EINTR);
    if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
    return (int64_t)n;
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

/* $SSH_ASKPASS run with the prompt, its first line of output the answer. */
static int64_t askpass(const char *prog, net_slice prompt, net_buf out) {
    char p[1024];
    if (cstring(prompt, p, sizeof p) < 0) return -1;
    int fds[2];
    if (pipe(fds) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        execlp(prog, prog, p, (char *)0);
        _exit(127);
    }
    close(fds[1]);
    int64_t n = 0;
    char ch;
    while (n < out.len && read(fds[0], &ch, 1) == 1 && ch != '\n' && ch != '\r') out.data[n++] = (uint8_t)ch;
    close(fds[0]);
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? n : -1;
}

/* A secret typed at the terminal, not echoed, or from $SSH_ASKPASS as
   OpenSSH's ssh has it: always with $SSH_ASKPASS_REQUIRE "force" or
   "prefer", never with "never", else when there is no terminal. Its
   length, or -1 for neither. */
int64_t tty_secret(net_slice prompt, net_buf out) {
    const char *prog = getenv("SSH_ASKPASS");
    const char *req = getenv("SSH_ASKPASS_REQUIRE");
    int use = prog && *prog && !(req && strcmp(req, "never") == 0);
    if (use && req && (strcmp(req, "force") == 0 || strcmp(req, "prefer") == 0)) return askpass(prog, prompt, out);
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) return use ? askpass(prog, prompt, out) : -1;
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

/* A child's signals as a login's should be, whatever the server was
   started with (nohup ignores SIGHUP, and the server itself ignores
   SIGPIPE): every disposition the default, nothing blocked. Ignored
   dispositions survive exec, and a child that ignores SIGHUP outlives its
   session. */
static void child_signals(void) {
    const int sigs[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGCHLD, SIGALRM, SIGTSTP, SIGTTIN, SIGTTOU, SIGUSR1, SIGUSR2 };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) signal(sigs[i], SIG_DFL);
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
}

/* A session's working directory, as OpenSSH's: the user's home ($HOME,
   which the server shares with its user), else the root. */
static void home_dir(void) {
    const char *h = getenv("HOME");
    if (!h || !*h || chdir(h) != 0) {
        if (chdir("/") != 0) _exit(127);
    }
}

/* Runs `cmd` with the user's shell (-c), or the shell itself for "",
   in the home directory, on three pipes: its stdin, stdout and stderr
   ends through the pointers.
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
        child_signals();
        dup2(pin[0], 0);
        dup2(pout[1], 1);
        dup2(perr[1], 2);
        close(pin[0]); close(pin[1]); close(pout[0]); close(pout[1]); close(perr[0]); close(perr[1]);
        put_env(env);
        home_dir();
        const char *sh = user_shell();
        if (c[0]) execl(sh, sh, "-c", c, (char *)NULL);
        else execl(sh, sh, "-l", (char *)NULL);
        _exit(127);
    }
    close(pin[0]); close(pout[1]); close(perr[1]);
    /* The child's stdin takes what fits (net_write_some): a blocking write
       there, with the child blocked writing a full stdout, would hang both. */
    fcntl(pin[1], F_SETFL, fcntl(pin[1], F_GETFL) | O_NONBLOCK);
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
        child_signals();
        int s = open(slave, O_RDWR);
        if (s < 0) _exit(127);
        ioctl(s, TIOCSCTTY, 0);
        ioctl(s, TIOCSWINSZ, &w);
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        if (s > 2) close(s);
        close(m);
        if (t[0]) setenv("TERM", t, 1);
        put_env(env);
        home_dir();
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

/* Ends a session's child: SIGHUP to its process group, up to two seconds
   to go, then SIGKILL. Its exit status, as proc_wait's. */
int32_t proc_end(int32_t pid) {
    if (pid <= 0) return 255;
    kill(-pid, SIGHUP);
    for (int i = 0; i < 200; i++) {
        int32_t st = proc_wait(pid, 0);
        if (st >= 0) return st;
        usleep(10000);
    }
    kill(-pid, SIGKILL);
    return proc_wait(pid, 1);
}

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

/* Reads a private file in one open: not through a symlink (O_NOFOLLOW),
   and then checked on the descriptor itself (fstat), so nothing can be
   swapped in between: a regular file, owned by this user, that no one else
   may read or write. O_NONBLOCK so that a FIFO there opens at once (and is
   refused as not a regular file) instead of waiting for a writer; it does
   nothing to a regular file's reads. Its length into out, or -1 when it is not there, -2
   when it cannot be opened, -3 not a regular file, -4 owned by another
   user, -5 group or others have access, -6 too long or unreadable. */
int64_t os_read_private(net_slice path, net_buf out) {
    char p[4096];
    if (cstring(path, p, sizeof p) < 0) return -2;
    int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno == ENOENT ? -1 : -2;
    struct stat st;
    int64_t r = 0;
    if (fstat(fd, &st) < 0) r = -2;
    else if (!S_ISREG(st.st_mode)) r = -3;
    else if (st.st_uid != geteuid()) r = -4;
    else if ((st.st_mode & 077) != 0) r = -5;
    else if (st.st_size > out.len) r = -6;
    while (r >= 0 && r < out.len) {
        ssize_t n = read(fd, out.data + r, (size_t)(out.len - r));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { r = -6; break; }
        if (n == 0) break;
        r += n;
    }
    close(fd);
    return r;
}

static int write_all(int fd, net_slice data) {
    int64_t off = 0;
    while (off < data.len) {
        ssize_t n = write(fd, data.data + off, (size_t)(data.len - off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        off += n;
    }
    return fsync(fd);
}

/* Writes a secret file, mode 0600 from the moment it exists, whatever the
   umask: never through a symlink, never readable by others before a
   chmod. With replace 0 the file must not exist yet (O_EXCL); with
   replace 1 the data goes to a new file beside it (mkstemp) that is then
   renamed over it, so the old file stays whole if anything fails. 0 or
   -1. */
int32_t os_write_private(net_slice path, net_slice data, int32_t replace) {
    char p[4096], tmp[4096 + 8];
    if (cstring(path, p, sizeof p) < 0) return -1;
    if (!replace) {
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        int bad = write_all(fd, data) < 0;
        if (close(fd) < 0) bad = 1;
        if (bad) { unlink(p); return -1; }
        return 0;
    }
    snprintf(tmp, sizeof tmp, "%s.XXXXXX", p);
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    int bad = fchmod(fd, 0600) < 0 || write_all(fd, data) < 0;
    if (close(fd) < 0) bad = 1;
    if (bad || rename(tmp, p) < 0) { unlink(tmp); return -1; }
    return 0;
}

int64_t os_home(net_buf out) {
    const char *h = getenv("HOME");
    if (!h) return 0;
    size_t l = strlen(h);
    if ((int64_t)l > out.len) l = (size_t)out.len;
    memcpy(out.data, h, l);
    return (int64_t)l;
}
