/* cgroups v2 wrapper: memory.max, pids.max, and event counters. */
#include "cgroup.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#define CG_ROOT "/sys/fs/cgroup"
#define CG_BASE CG_ROOT "/securerun"

int cg_init(void)
{
    struct statfs fs;
    if (statfs(CG_ROOT, &fs) != 0 || fs.f_type != CGROUP2_SUPER_MAGIC) return -1;
    write_file(CG_ROOT "/cgroup.subtree_control", "+memory +pids"); /* may already be on */
    if (mkdir(CG_BASE, 0755) != 0 && errno != EEXIST) return -1;
    if (write_file(CG_BASE "/cgroup.subtree_control", "+memory +pids") != 0) return -1;
    return 0;
}

int cg_create(int id, long mem_mb, int pids_max, char *path, size_t n)
{
    char f[512], v[64];
    snprintf(path, n, CG_BASE "/job%d_%d", (int)getpid(), id);
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;

    snprintf(f, sizeof f, "%s/memory.max", path);
    snprintf(v, sizeof v, "%ld", mem_mb * 1024 * 1024);
    if (write_file(f, v) != 0) return -1;

    snprintf(f, sizeof f, "%s/memory.swap.max", path);       /* no swap escape  */
    write_file(f, "0");
    snprintf(f, sizeof f, "%s/memory.oom.group", path);      /* kill all at once */
    write_file(f, "1");

    snprintf(f, sizeof f, "%s/pids.max", path);
    snprintf(v, sizeof v, "%d", pids_max);
    if (write_file(f, v) != 0) return -1;
    return 0;
}

/* Writing "0" to cgroup.procs moves the *calling* process. */
int cg_join_self(const char *path)
{
    char f[512];
    snprintf(f, sizeof f, "%s/cgroup.procs", path);
    return write_file(f, "0");
}

long cg_kv(const char *path, const char *file, const char *key)
{
    char f[512];
    snprintf(f, sizeof f, "%s/%s", path, file);
    char *s = read_file(f, NULL);
    if (!s) return -1;
    long val = -1;
    size_t kl = strlen(key);
    for (char *p = s; p && *p; ) {
        if (strncmp(p, key, kl) == 0 && (p[kl] == ' ' || p[kl] == '\n' || p[kl] == 0)) {
            val = strtol(p + kl, NULL, 10);
            break;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    free(s);
    return val;
}

void cg_destroy(const char *path)
{
    char f[512];
    snprintf(f, sizeof f, "%s/cgroup.kill", path);
    write_file(f, "1");                                  /* kernel >= 5.14 */
    for (int i = 0; i < 100; i++) {
        if (rmdir(path) == 0 || errno == ENOENT) return;
        usleep(10000);
    }
}
