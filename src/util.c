#include "util.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ftw.h>
#include <time.h>
#include <sys/stat.h>

char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, n = 0, r;
    char *b = malloc(cap + 1);
    if (!b) { fclose(f); return NULL; }
    while ((r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            cap *= 2;
            char *t = realloc(b, cap + 1);
            if (!t) { free(b); fclose(f); return NULL; }
            b = t;
        }
    }
    b[n] = 0;
    fclose(f);
    if (len) *len = n;
    return b;
}

/* One single write() call: cgroup control files require that. */
int write_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    close(fd);
    return n < 0 ? -1 : 0;
}

int copy_file(const char *from, const char *to, mode_t mode)
{
    size_t len;
    char *b = read_file(from, &len);
    if (!b) return -1;
    int fd = open(to, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) { free(b); return -1; }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, b + off, len - off);
        if (w <= 0) { close(fd); free(b); return -1; }
        off += (size_t)w;
    }
    fchmod(fd, mode);
    close(fd);
    free(b);
    return 0;
}

static int rm_cb(const char *p, const struct stat *sb, int type, struct FTW *f)
{
    (void)sb; (void)type; (void)f;
    return remove(p);
}
int rm_rf(const char *path) { return nftw(path, rm_cb, 16, FTW_DEPTH | FTW_PHYS); }

double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

const char *verdict_name(verdict_t v)
{
    switch (v) {
    case V_AC:  return "Accepted";
    case V_WA:  return "Wrong Answer";
    case V_TLE: return "Time Limit Exceeded";
    case V_MLE: return "Memory Limit Exceeded";
    case V_RLE: return "Resource Limit Exceeded";
    case V_OLE: return "Output Limit Exceeded";
    case V_RE:  return "Runtime Error";
    case V_CE:  return "Compile Error";
    case V_SYSERR: return "System Error";
    default:    return "Pending";
    }
}
