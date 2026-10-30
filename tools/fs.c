/* The file system for tools/sftp_server.goose and tools/scp.goose: files
   by descriptor (open, pread, pwrite, close, fstat, ...), paths (stat,
   lstat, chmod, utimes, rename, link, symlink, readlink, realpath, mkdir,
   ...), directories read through a table of open ones, and users' home
   directories. POSIX: macOS and Linux. Each function returns 0 (or a count,
   a descriptor) on success and -errno on failure, so that the caller can
   map the error; strings arrive as Goose slices, { data, len }, not
   NUL-terminated, and a path holding a NUL byte is refused (EINVAL), since
   C would read only its first part. */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct { const uint8_t *data; int64_t len; } fs_slice;
typedef struct { uint8_t *data; int64_t len; } fs_buf;
typedef struct { uint64_t *data; int64_t len; } fs_u64s;

#define FS_PATH_MAX 4096

/* A path as a C string in p (FS_PATH_MAX bytes): 0, or -EINVAL for one
   holding a NUL, -ENAMETOOLONG for one too long. The empty path stays
   empty (the call then fails with ENOENT, as POSIX has it). */
static int fs_path(fs_slice s, char *p) {
    if (s.len < 0) return -EINVAL;
    if (s.len >= FS_PATH_MAX) return -ENAMETOOLONG;
    if (s.len > 0 && memchr(s.data, 0, (size_t)s.len)) return -EINVAL;
    memcpy(p, s.data, (size_t)s.len);
    p[s.len] = 0;
    return 0;
}

static int64_t fail(void) { return -(int64_t)errno; }

/* --- Files ------------------------------------------------------------------ */

/* SFTP's pflags (READ 1, WRITE 2, APPEND 4, CREAT 8, TRUNC 16, EXCL 32)
   as open(2)'s; mode for a file it creates. */
int32_t fs_open(fs_slice path, uint32_t pflags, uint32_t mode) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    int flags;
    if ((pflags & 1) && (pflags & 2)) flags = O_RDWR;
    else if (pflags & 2) flags = O_WRONLY;
    else flags = O_RDONLY;
    if (pflags & 4) flags |= O_APPEND;
    if (pflags & 8) flags |= O_CREAT;
    if (pflags & 16) flags |= O_TRUNC;
    if (pflags & 32) flags |= O_EXCL;
    int fd = open(p, flags | O_NOCTTY, (mode_t)(mode & 07777));
    return fd < 0 ? (int32_t)fail() : fd;
}

int32_t fs_close(int32_t fd) { return close(fd) < 0 ? (int32_t)fail() : 0; }

/* Reads at offset until buf is full or the file ends: how many bytes (0 at
   the end), or -errno. */
int64_t fs_pread(int32_t fd, fs_buf buf, uint64_t offset) {
    int64_t got = 0;
    while (got < buf.len) {
        ssize_t n = pread(fd, buf.data + got, (size_t)(buf.len - got), (off_t)(offset + (uint64_t)got));
        if (n < 0) { if (errno == EINTR) continue; return got > 0 ? got : fail(); }
        if (n == 0) break;
        got += n;
    }
    return got;
}

/* Writes all of data at offset (at the end, for a file opened to append):
   0, or -errno. */
int64_t fs_pwrite(int32_t fd, fs_slice data, uint64_t offset, int32_t append) {
    int64_t put = 0;
    while (put < data.len) {
        ssize_t n = append ? write(fd, data.data + put, (size_t)(data.len - put))
                           : pwrite(fd, data.data + put, (size_t)(data.len - put), (off_t)(offset + (uint64_t)put));
        if (n < 0) { if (errno == EINTR) continue; return fail(); }
        put += n;
    }
    return 0;
}

/* st[0..7]: size, uid, gid, mode, atime, mtime, nlink. */
static void fill(const struct stat *s, fs_u64s st) {
    uint64_t v[7] = { (uint64_t)s->st_size, s->st_uid, s->st_gid, s->st_mode, (uint64_t)s->st_atime,
                      (uint64_t)s->st_mtime, (uint64_t)s->st_nlink };
    for (int i = 0; i < 7 && i < st.len; i++) st.data[i] = v[i];
}

int32_t fs_stat(fs_slice path, int32_t follow, fs_u64s st) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    struct stat s;
    if ((follow ? stat(p, &s) : lstat(p, &s)) < 0) return (int32_t)fail();
    fill(&s, st);
    return 0;
}

int32_t fs_fstat(int32_t fd, fs_u64s st) {
    struct stat s;
    if (fstat(fd, &s) < 0) return (int32_t)fail();
    fill(&s, st);
    return 0;
}

/* SETSTAT's parts, on a path (follow 0: the link itself) or, with fd >= 0,
   on the open file. */
int32_t fs_truncate(fs_slice path, int32_t fd, uint64_t size) {
    if (fd >= 0) return ftruncate(fd, (off_t)size) < 0 ? (int32_t)fail() : 0;
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return truncate(p, (off_t)size) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_chmod(fs_slice path, int32_t fd, uint32_t mode, int32_t follow) {
    if (fd >= 0) return fchmod(fd, (mode_t)(mode & 07777)) < 0 ? (int32_t)fail() : 0;
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return fchmodat(AT_FDCWD, p, (mode_t)(mode & 07777), follow ? 0 : AT_SYMLINK_NOFOLLOW) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_chown(fs_slice path, int32_t fd, uint32_t uid, uint32_t gid, int32_t follow) {
    if (fd >= 0) return fchown(fd, (uid_t)uid, (gid_t)gid) < 0 ? (int32_t)fail() : 0;
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return (follow ? chown(p, (uid_t)uid, (gid_t)gid) : lchown(p, (uid_t)uid, (gid_t)gid)) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_utimes(fs_slice path, int32_t fd, uint64_t atime, uint64_t mtime, int32_t follow) {
    struct timespec ts[2];
    ts[0].tv_sec = (time_t)atime; ts[0].tv_nsec = 0;
    ts[1].tv_sec = (time_t)mtime; ts[1].tv_nsec = 0;
    if (fd >= 0) return futimens(fd, ts) < 0 ? (int32_t)fail() : 0;
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return utimensat(AT_FDCWD, p, ts, follow ? 0 : AT_SYMLINK_NOFOLLOW) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_fsync(int32_t fd) { return fsync(fd) < 0 ? (int32_t)fail() : 0; }

/* --- Paths -------------------------------------------------------------------- */

int32_t fs_unlink(fs_slice path) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return unlink(p) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_mkdir(fs_slice path, uint32_t mode) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return mkdir(p, (mode_t)(mode & 07777)) < 0 ? (int32_t)fail() : 0;
}

int32_t fs_rmdir(fs_slice path) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    return rmdir(p) < 0 ? (int32_t)fail() : 0;
}

/* kind 0: rename(2), replacing what is at `to`; 1: link(2); 2:
   symlink(from, to), from being the link's target. */
int32_t fs_two(fs_slice from, fs_slice to, int32_t kind) {
    char a[FS_PATH_MAX], b[FS_PATH_MAX];
    int r = fs_path(from, a);
    if (r < 0) return r;
    r = fs_path(to, b);
    if (r < 0) return r;
    int rc = kind == 0 ? rename(a, b) : kind == 1 ? link(a, b) : symlink(a, b);
    return rc < 0 ? (int32_t)fail() : 0;
}

/* readlink (kind 0) and realpath (kind 1) into out: the length, or -errno
   (-ENAMETOOLONG for a result longer than out). */
int64_t fs_resolve(fs_slice path, fs_buf out, int32_t kind) {
    char p[FS_PATH_MAX], res[PATH_MAX + 1];
    int r = fs_path(path, p);
    if (r < 0) return r;
    int64_t n;
    if (kind == 0) {
        ssize_t k = readlink(p, res, sizeof res - 1);
        if (k < 0) return fail();
        n = k;
    } else {
        if (!realpath(p, res)) return fail();
        n = (int64_t)strlen(res);
    }
    if (n > out.len) return -ENAMETOOLONG;
    memcpy(out.data, res, (size_t)n);
    return n;
}

/* statvfs of a path, or of fd if >= 0, as OpenSSH's statvfs@openssh.com
   sends it: bsize, frsize, blocks, bfree, bavail, files, ffree, favail,
   fsid, flag (1: read-only, 2: no setuid), namemax. */
int32_t fs_statvfs(fs_slice path, int32_t fd, fs_u64s out) {
    struct statvfs s;
    if (fd >= 0) {
        if (fstatvfs(fd, &s) < 0) return (int32_t)fail();
    } else {
        char p[FS_PATH_MAX];
        int r = fs_path(path, p);
        if (r < 0) return r;
        if (statvfs(p, &s) < 0) return (int32_t)fail();
    }
    uint64_t flag = ((s.f_flag & ST_RDONLY) ? 1 : 0) | ((s.f_flag & ST_NOSUID) ? 2 : 0);
    uint64_t v[11] = { s.f_bsize, s.f_frsize, s.f_blocks, s.f_bfree, s.f_bavail, s.f_files, s.f_ffree, s.f_favail,
                       (uint64_t)s.f_fsid, flag, s.f_namemax };
    for (int i = 0; i < 11 && i < out.len; i++) out.data[i] = v[i];
    return 0;
}

/* --- Directories ------------------------------------------------------------------- */

#define FS_DIRS 64
static DIR *dirs[FS_DIRS];

/* A directory opened: its slot in the table, or -errno (-EMFILE when the
   table is full). */
int32_t fs_opendir(fs_slice path) {
    char p[FS_PATH_MAX];
    int r = fs_path(path, p);
    if (r < 0) return r;
    int slot = -1;
    for (int i = 0; i < FS_DIRS; i++) if (!dirs[i]) { slot = i; break; }
    if (slot < 0) return -EMFILE;
    DIR *d = opendir(p);
    if (!d) return (int32_t)fail();
    dirs[slot] = d;
    return slot;
}

/* The next entry's name into out: its length, 0 at the end, or -errno.
   "." and ".." are entries too, as readdir has them. */
int64_t fs_readdir(int32_t slot, fs_buf out) {
    if (slot < 0 || slot >= FS_DIRS || !dirs[slot]) return -EBADF;
    errno = 0;
    struct dirent *e = readdir(dirs[slot]);
    if (!e) return errno ? fail() : 0;
    int64_t n = (int64_t)strlen(e->d_name);
    if (n > out.len) return -ENAMETOOLONG;
    memcpy(out.data, e->d_name, (size_t)n);
    return n;
}

int32_t fs_closedir(int32_t slot) {
    if (slot < 0 || slot >= FS_DIRS || !dirs[slot]) return -EBADF;
    int rc = closedir(dirs[slot]);
    dirs[slot] = NULL;
    return rc < 0 ? (int32_t)fail() : 0;
}

/* --- Users ----------------------------------------------------------------------- */

/* The home directory of a user ("" for the one running this: $HOME, else
   the password database's), into out: its length, or -ENOENT. */
int64_t fs_home(fs_slice user, fs_buf out) {
    char u[256];
    if (user.len >= (int64_t)sizeof u || (user.len > 0 && memchr(user.data, 0, (size_t)user.len))) return -ENOENT;
    memcpy(u, user.data, (size_t)user.len);
    u[user.len] = 0;
    const char *h = NULL;
    if (!u[0]) {
        h = getenv("HOME");
        if (!h || !*h) { struct passwd *pw = getpwuid(getuid()); h = pw ? pw->pw_dir : NULL; }
    } else {
        struct passwd *pw = getpwnam(u);
        h = pw ? pw->pw_dir : NULL;
    }
    if (!h) return -ENOENT;
    int64_t n = (int64_t)strlen(h);
    if (n > out.len) return -ENAMETOOLONG;
    memcpy(out.data, h, (size_t)n);
    return n;
}

/* The name of a user (kind 0) or group (1) by id, into out: its length,
   or 0 when there is none. */
int64_t fs_id_name(uint32_t id, int32_t kind, fs_buf out) {
    const char *name = NULL;
    if (kind == 0) { struct passwd *pw = getpwuid((uid_t)id); name = pw ? pw->pw_name : NULL; }
    else { struct group *gr = getgrgid((gid_t)id); name = gr ? gr->gr_name : NULL; }
    if (!name) return 0;
    int64_t n = (int64_t)strlen(name);
    if (n > out.len) return 0;
    memcpy(out.data, name, (size_t)n);
    return n;
}

/* The file-creation mask, which this process keeps as it found it. */
uint32_t fs_umask(void) {
    mode_t m = umask(0);
    umask(m);
    return (uint32_t)m;
}

/* errno's values that SFTP's status codes tell apart, so that the Goose
   side can map them without knowing this platform's numbers. */
int32_t fs_errno(int32_t which) {
    switch (which) {
    case 0: return ENOENT;  case 1: return ENOTDIR; case 2: return EBADF;  case 3: return ELOOP;
    case 4: return EPERM;   case 5: return EACCES;  case 6: return EFAULT; case 7: return ENAMETOOLONG;
    case 8: return EINVAL;  case 9: return ENOSYS;  case 10: return EEXIST; case 11: return EISDIR;
    case 12: return ENOTEMPTY; case 13: return EXDEV; case 14: return EOPNOTSUPP;
    }
    return 0;
}
