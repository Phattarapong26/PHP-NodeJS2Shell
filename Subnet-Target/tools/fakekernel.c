/*
 * fakekernel.c - LD_PRELOAD kernel fingerprint simulator
 *
 * ใช้สำหรับทดสอบ "ตรรกะการตรวจจับ" ของเครื่องมือ VA ที่อ่าน kernel version
 * จาก uname(2) และไฟล์ใน /proc, /etc, /lib/modules, /var/lib/dpkg
 * โดยไม่ต้องเปลี่ยน kernel จริง (ทำไม่ได้ในคอนเทนเนอร์)
 *
 * env:
 *   FAKEKERNEL_ROOT      โฟลเดอร์รากของโปรไฟล์จำลอง (มี /proc/version ฯลฯ อยู่ข้างใน)
 *   FAKEKERNEL_RELEASE   ค่า release ที่จะคืนจาก uname()  e.g. 6.8.0-149-generic
 *   FAKEKERNEL_VERSION   ค่า version ที่จะคืนจาก uname()
 *   FAKEKERNEL_SYSNAME / FAKEKERNEL_MACHINE / FAKEKERNEL_HOSTNAME  (optional)
 *
 * ข้อจำกัด: ใช้ได้กับโปรแกรมที่ link แบบ dynamic เท่านั้น (Go/Rust แบบ static จะไม่สนใจ)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>

/* ไฟล์/ไดเรกทอรีที่ยอมให้ redirect ไปยังโปรไฟล์จำลอง */
static const char *kTargets[] = {
    "/proc/version",
    "/proc/sys/kernel/osrelease",
    "/proc/sys/kernel/version",
    "/proc/sys/kernel/hostname",
    "/proc/sys/net/mptcp/enabled",
    "/proc/sys/net/ipv4/tcp_migrate_req",
    "/etc/os-release",
    "/etc/lsb-release",
    "/etc/debian_version",
    "/etc/redhat-release",
    "/etc/system-release",
    "/etc/almalinux-release",
    "/var/lib/dpkg/status",
    "/lib/modules",
    NULL
};


/* ---------------------------------------------------------------------------
 * โหลดค่าจาก /etc/lab-kernel.env เมื่อไม่ได้ตั้ง env var (โหมด ld.so.preload)
 * รูปแบบไฟล์: FAKEKERNEL_RELEASE="5.15.0-203-generic"
 * ------------------------------------------------------------------------- */
struct fk_conf {
    char root[256], release[128], version[256], hostname[128], machine[32];
    char sysname[32];
    int loaded;
};
static struct fk_conf g_cfg;

static void fk_trim(char *s)
{
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == ' ' || s[n-1] == '\t')) s[--n] = '\0';
    if (n >= 2 && s[0] == '"' && s[n-1] == '"') { memmove(s, s+1, n-2); s[n-2] = '\0'; }
}

static void fk_assign(const char *k, const char *v)
{
    char buf[256];
    snprintf(buf, sizeof buf, "%s", v);
    fk_trim(buf);
    if (!strcmp(k, "FAKEKERNEL_ROOT"))     snprintf(g_cfg.root, sizeof g_cfg.root, "%s", buf);
    else if (!strcmp(k, "FAKEKERNEL_RELEASE"))  snprintf(g_cfg.release, sizeof g_cfg.release, "%s", buf);
    else if (!strcmp(k, "FAKEKERNEL_VERSION"))  snprintf(g_cfg.version, sizeof g_cfg.version, "%s", buf);
    else if (!strcmp(k, "FAKEKERNEL_HOSTNAME")) snprintf(g_cfg.hostname, sizeof g_cfg.hostname, "%s", buf);
    else if (!strcmp(k, "FAKEKERNEL_MACHINE"))  snprintf(g_cfg.machine, sizeof g_cfg.machine, "%s", buf);
    else if (!strcmp(k, "FAKEKERNEL_SYSNAME"))  snprintf(g_cfg.sysname, sizeof g_cfg.sysname, "%s", buf);
}

static void fk_load(void)
{
    if (g_cfg.loaded) return;
    g_cfg.loaded = 1;
    FILE *f = fopen("/etc/lab-kernel.env", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '=');
        if (!eq || line[0] == '#') continue;
        *eq = '\0';
        fk_assign(line, eq + 1);
    }
    fclose(f);
}

static const char *fk_get(const char *env, char *fallback, size_t n)
{
    const char *v = getenv(env);
    if (v && v[0]) return v;
    fk_load();
    if (fallback && fallback[0]) return fallback;
    (void)n;
    return NULL;
}

static const char *fk_map(const char *path, char *buf, size_t n)
{
    const char *root = getenv("FAKEKERNEL_ROOT");
    if (!root || !root[0]) { fk_load(); root = g_cfg.root; }
    if (!root || !root[0] || !path) return path;
    for (int i = 0; kTargets[i]; i++) {
        if (strcmp(path, kTargets[i]) == 0) {
            snprintf(buf, n, "%s%s", root, path);
            return buf;
        }
    }
    return path;
}

#define REAL(name) \
    static __typeof__(name) *real_##name = NULL; \
    if (!real_##name) real_##name = (__typeof__(name) *)dlsym(RTLD_NEXT, #name);

/* ------------------------------- uname ------------------------------- */
int uname(struct utsname *buf)
{
    REAL(uname);
    if (!real_uname) { errno = ENOSYS; return -1; }
    int rc = real_uname(buf);
    if (rc == 0) {
        fk_load();
        const char *v;
        if ((v = fk_get("FAKEKERNEL_SYSNAME", g_cfg.sysname, sizeof g_cfg.sysname))) snprintf(buf->sysname,  sizeof buf->sysname,  "%s", v);
        if ((v = fk_get("FAKEKERNEL_HOSTNAME", g_cfg.hostname, sizeof g_cfg.hostname))) snprintf(buf->nodename, sizeof buf->nodename, "%s", v);
        if ((v = fk_get("FAKEKERNEL_RELEASE", g_cfg.release, sizeof g_cfg.release))) snprintf(buf->release,  sizeof buf->release,  "%s", v);
        if ((v = fk_get("FAKEKERNEL_VERSION", g_cfg.version, sizeof g_cfg.version))) snprintf(buf->version,  sizeof buf->version,  "%s", v);
        if ((v = fk_get("FAKEKERNEL_MACHINE", g_cfg.machine, sizeof g_cfg.machine))) snprintf(buf->machine,  sizeof buf->machine,  "%s", v);
    }
    return rc;
}

/* ------------------------------- open -------------------------------- */
int open(const char *path, int flags, ...)
{
    REAL(open);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    char b[4096];
    return real_open(fk_map(path, b, sizeof b), flags, mode);
}

int open64(const char *path, int flags, ...)
{
    REAL(open64);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    char b[4096];
    return real_open64(fk_map(path, b, sizeof b), flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    REAL(openat);
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    char b[4096];
    return real_openat(dirfd, fk_map(path, b, sizeof b), flags, mode);
}

/* ------------------------------- fopen ------------------------------- */
FILE *fopen(const char *path, const char *mode)
{
    REAL(fopen);
    char b[4096];
    return real_fopen(fk_map(path, b, sizeof b), mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    REAL(fopen64);
    char b[4096];
    return real_fopen64(fk_map(path, b, sizeof b), mode);
}

/* ------------------------------- stat -------------------------------- */
int stat(const char *path, struct stat *st)
{
    REAL(stat);
    char b[4096];
    return real_stat(fk_map(path, b, sizeof b), st);
}

int lstat(const char *path, struct stat *st)
{
    REAL(lstat);
    char b[4096];
    return real_lstat(fk_map(path, b, sizeof b), st);
}

int stat64(const char *path, struct stat64 *st)
{
    REAL(stat64);
    char b[4096];
    return real_stat64(fk_map(path, b, sizeof b), st);
}

int lstat64(const char *path, struct stat64 *st)
{
    REAL(lstat64);
    char b[4096];
    return real_lstat64(fk_map(path, b, sizeof b), st);
}

int access(const char *path, int amode)
{
    REAL(access);
    char b[4096];
    return real_access(fk_map(path, b, sizeof b), amode);
}

/* ------------------------------ opendir ------------------------------ */
DIR *opendir(const char *path)
{
    REAL(opendir);
    char b[4096];
    return real_opendir(fk_map(path, b, sizeof b));
}


/* ---------------------------- statx/fstatat ---------------------------
 * coreutils รุ่นใหม่ (ls, stat, find) ใช้ statx() จึงต้องดักไว้ด้วย
 * -------------------------------------------------------------------- */
int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *st)
{
    REAL(statx);
    char b[4096];
    return real_statx(dirfd, fk_map(path, b, sizeof b), flags, mask, st);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    REAL(fstatat);
    char b[4096];
    return real_fstatat(dirfd, fk_map(path, b, sizeof b), st, flags);
}

int __xstat(int ver, const char *path, struct stat *st)
{
    (void)ver;
    char b[4096];
    return stat(fk_map(path, b, sizeof b), st);
}

int __lxstat(int ver, const char *path, struct stat *st)
{
    (void)ver;
    char b[4096];
    return lstat(fk_map(path, b, sizeof b), st);
}

/* ------------------------------ readlink ----------------------------- */
ssize_t readlink(const char *path, char *out, size_t n)
{
    REAL(readlink);
    char b[4096];
    return real_readlink(fk_map(path, b, sizeof b), out, n);
}
