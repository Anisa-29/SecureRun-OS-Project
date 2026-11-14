/* Phases 1,3,4,5: build the sandbox, run the program, watch it, decode what happened.
 *
 *  clone() flags give the child NEW namespaces (pid, mount, net, ipc, uts).
 *  Inside the child:  join cgroup -> chroot -> dup2 fds -> rlimits -> drop root -> exec
 *  Parent:            poll pipe + wait4(WNOHANG) + wall-clock timer, then read cgroup counters.
 */
#include "common.h"
#include "util.h"
#include "cgroup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>

#define NOBODY 65534
#define STACK_SZ (1 << 20)

typedef struct {
    const char *rootdir;
    const char *cg_path;      /* NULL when cgroups unavailable */
    int in_fd, out_fd, null_fd, err_fd;
    int cpu_s;
    long mem_mb;
} child_args_t;

static int die(int fd, const char *msg)
{
    ssize_t r = write(fd, msg, strlen(msg));
    (void)r;
    _exit(120);
}

/* Runs as PID 1 of the new PID namespace. */
static int child_main(void *arg)
{
    child_args_t *a = arg;
    struct rlimit rl;

    if (a->cg_path && cg_join_self(a->cg_path) != 0) die(a->err_fd, "cannot join cgroup");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) die(a->err_fd, "mount private failed");
    if (sethostname("sandbox", 7) != 0) { /* cosmetic */ }

    if (chroot(a->rootdir) != 0 || chdir("/") != 0) die(a->err_fd, "chroot failed");

    if (dup2(a->in_fd, 0) < 0 || dup2(a->out_fd, 1) < 0 || dup2(a->null_fd, 2) < 0)
        die(a->err_fd, "dup2 failed");

    rl.rlim_cur = a->cpu_s;  rl.rlim_max = a->cpu_s + 1;       /* SIGXCPU, then SIGKILL */
    setrlimit(RLIMIT_CPU, &rl);
    rl.rlim_cur = rl.rlim_max = 16UL << 20;  setrlimit(RLIMIT_FSIZE, &rl);
    rl.rlim_cur = rl.rlim_max = 64;          setrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = rl.rlim_max = 0;           setrlimit(RLIMIT_CORE, &rl);
    if (!a->cg_path) {                       /* fallback safety net without cgroups */
        rl.rlim_cur = rl.rlim_max = (rlim_t)a->mem_mb << 20; setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = 32;                      setrlimit(RLIMIT_NPROC, &rl);
    }

    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    setgroups(0, NULL);
    if (setgid(NOBODY) != 0 || setuid(NOBODY) != 0) die(a->err_fd, "drop privileges failed");

    char *argv[] = { "prog", NULL };
    char *envp[] = { NULL };
    execve("/prog", argv, envp);
    die(a->err_fd, "exec failed");
    return 0;
}

static void drain(int fd, char *buf, size_t *len, size_t cap, int *eof, int *overflow)
{
    char tmp[4096];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof tmp);
        if (n > 0) {
            if (*len + (size_t)n > cap) {
                size_t room = cap - *len;
                memcpy(buf + *len, tmp, room);
                *len = cap;
                *overflow = 1;
            } else { memcpy(buf + *len, tmp, (size_t)n); *len += (size_t)n; }
        } else if (n == 0) { *eof = 1; return; }
        else return;                                   /* EAGAIN */
    }
}

void run_sandboxed(job_t *j, const char *rootdir, char **out)
{
    char cgpath[256] = "";
    int use_cg = 0;
    *out = NULL;

    if (g_cfg.use_cgroup) {
        if (cg_create(j->id, g_cfg.mem_mb, g_cfg.pids_max, cgpath, sizeof cgpath) == 0) use_cg = 1;
        else { j->verdict = V_SYSERR; snprintf(j->detail, sizeof j->detail, "cgroup creation failed"); return; }
    }

    int in_fd = open(j->input, O_RDONLY | O_CLOEXEC);
    int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    int outp[2], errp[2];
    if (in_fd < 0 || null_fd < 0 || pipe2(outp, O_CLOEXEC) || pipe2(errp, O_CLOEXEC)) {
        j->verdict = V_SYSERR;
        snprintf(j->detail, sizeof j->detail, "cannot open input/pipes: %s", strerror(errno));
        if (use_cg) cg_destroy(cgpath);
        return;
    }

    child_args_t a = { rootdir, use_cg ? cgpath : NULL, in_fd, outp[1], null_fd, errp[1],
                       g_cfg.time_s, g_cfg.mem_mb };
    char *stack = malloc(STACK_SZ);
    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | SIGCHLD;
    double start = now_ms();
    pid_t pid = clone(child_main, stack + STACK_SZ, flags, &a);
    if (pid < 0) {
        j->verdict = V_SYSERR;
        snprintf(j->detail, sizeof j->detail, "clone failed: %s (need root?)", strerror(errno));
        free(stack); close(in_fd); close(null_fd);
        close(outp[0]); close(outp[1]); close(errp[0]); close(errp[1]);
        if (use_cg) cg_destroy(cgpath);
        return;
    }
    close(outp[1]); close(errp[1]); close(in_fd); close(null_fd);

    int rfd = outp[0];
    fcntl(rfd, F_SETFL, O_NONBLOCK);
    fcntl(errp[0], F_SETFL, O_NONBLOCK);

    char *buf = malloc(g_cfg.out_cap + 1);
    size_t olen = 0;
    int eof = 0, overflow = 0, reason = 0;   /* reason 1 = wall timeout, 2 = output flood */
    int status = 0, exited = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    double wall_ms = g_cfg.time_s * 2000.0;

    while (!exited) {
        if (!eof) {
            struct pollfd p = { rfd, POLLIN, 0 };
            poll(&p, 1, 20);
            drain(rfd, buf, &olen, g_cfg.out_cap, &eof, &overflow);
        } else usleep(10000);

        if (wait4(pid, &status, WNOHANG, &ru) == pid) { exited = 1; break; }

        if (overflow && !reason) { reason = 2; kill(pid, SIGKILL); }
        else if (!reason && now_ms() - start > wall_ms) { reason = 1; kill(pid, SIGKILL); }
    }
    drain(rfd, buf, &olen, g_cfg.out_cap, &eof, &overflow);
    buf[olen] = 0;

    /* did the child fail before exec()? */
    char emsg[128] = "";
    ssize_t en = read(errp[0], emsg, sizeof emsg - 1);
    if (en > 0) emsg[en] = 0;
    close(rfd); close(errp[0]); free(stack);

    j->cpu_ms = ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0
              + ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0;
    j->mem_kb = ru.ru_maxrss;

    long oom = 0, pmax = 0;
    if (use_cg) {
        oom  = cg_kv(cgpath, "memory.events", "oom_kill");
        pmax = cg_kv(cgpath, "pids.events", "max");
        long peak = cg_kv(cgpath, "memory.peak", "");      /* single-value file */
        if (peak <= 0) {
            char f[320]; snprintf(f, sizeof f, "%s/memory.peak", cgpath);
            char *s = read_file(f, NULL);
            if (s) { peak = strtol(s, NULL, 10); free(s); }
        }
        if (peak > 0) j->mem_kb = peak / 1024;
        cg_destroy(cgpath);
    }

    /* ---- verdict priority: SYSERR > MLE > RLE > OLE > TLE > RE > (compare) ---- */
    if (en > 0) {
        j->verdict = V_SYSERR;
        snprintf(j->detail, sizeof j->detail, "sandbox setup: %s", emsg);
    } else if (oom > 0) {
        j->verdict = V_MLE;
        snprintf(j->detail, sizeof j->detail, "killed by cgroup OOM (limit %ld MB)", g_cfg.mem_mb);
    } else if (pmax > 0) {
        j->verdict = V_RLE;
        snprintf(j->detail, sizeof j->detail, "pids.max (%d) hit: fork bomb / too many processes", g_cfg.pids_max);
    } else if (reason == 2) {
        j->verdict = V_OLE;
        snprintf(j->detail, sizeof j->detail, "output exceeded %zu bytes", g_cfg.out_cap);
    } else if (reason == 1) {
        j->verdict = V_TLE;
        snprintf(j->detail, sizeof j->detail, "wall-clock limit %ds exceeded", g_cfg.time_s * 2);
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        /* PID 1 of a namespace ignores SIGXCPU, so the hard limit's SIGKILL is what arrives. */
        if (sig == SIGXCPU || (sig == SIGKILL && j->cpu_ms >= g_cfg.time_s * 1000.0 - 50)) {
            j->verdict = V_TLE;
            snprintf(j->detail, sizeof j->detail, "CPU limit %ds exceeded", g_cfg.time_s);
        } else {
            j->verdict = V_RE;
            snprintf(j->detail, sizeof j->detail, "killed by signal %d (%s)", sig, strsignal(sig));
        }
    } else if (WEXITSTATUS(status) != 0) {
        j->verdict = V_RE;
        snprintf(j->detail, sizeof j->detail, "non-zero exit code %d", WEXITSTATUS(status));
    } else {
        j->verdict = V_PENDING;                    /* judge.c compares output */
    }
    *out = buf;
}
