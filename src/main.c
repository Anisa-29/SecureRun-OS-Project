/* SecureRun: sandboxed code execution & auto-grading engine.
 * Phase 7: semaphore-limited worker pool (one pthread per submission, N run at once). */
#include "common.h"
#include "cgroup.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>

config_t g_cfg = { .time_s = 2, .mem_mb = 64, .pids_max = 32, .workers = 4,
                   .use_cgroup = 1, .out_cap = 1 << 20 };
static sem_t slots;

static void *worker(void *arg)
{
    job_t *j = arg;
    sem_wait(&slots);            /* wait for a free judging slot */
    judge_job(j);
    sem_post(&slots);            /* release it                   */
    return NULL;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: sudo %s [-t cpu_seconds] [-m mem_MB] [-p max_pids] [-j workers] [-c]\n"
        "               <sub.c> <input> <expected> [<sub.c> <input> <expected> ...]\n"
        "  -c  disable cgroups (rlimit-only fallback, NOT safe against fork bombs)\n", p);
}

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "t:m:p:j:ch")) != -1) {
        switch (opt) {
        case 't': g_cfg.time_s = atoi(optarg); break;
        case 'm': g_cfg.mem_mb = atol(optarg); break;
        case 'p': g_cfg.pids_max = atoi(optarg); break;
        case 'j': g_cfg.workers = atoi(optarg); break;
        case 'c': g_cfg.use_cgroup = 0; break;
        default:  usage(argv[0]); return 2;
        }
    }
    int rest = argc - optind;
    if (rest < 3 || rest % 3 != 0 || g_cfg.time_s < 1 || g_cfg.workers < 1) { usage(argv[0]); return 2; }
    if (geteuid() != 0) { fprintf(stderr, "securerun needs root (namespaces, chroot, cgroups). Use sudo.\n"); return 1; }

    umask(022);
    if (g_cfg.use_cgroup && cg_init() != 0) {
        fprintf(stderr, "warning: cgroups v2 unavailable -> rlimit-only fallback (fork bombs NOT contained)\n");
        g_cfg.use_cgroup = 0;
    }
    snprintf(g_cfg.workdir, sizeof g_cfg.workdir, "/tmp/securerun_%d", (int)getpid());
    mkdir(g_cfg.workdir, 0755); chmod(g_cfg.workdir, 0755);

    int n = rest / 3;
    job_t *jobs = calloc((size_t)n, sizeof *jobs);
    pthread_t *th = calloc((size_t)n, sizeof *th);
    sem_init(&slots, 0, (unsigned)g_cfg.workers);

    for (int i = 0; i < n; i++) {
        jobs[i].id = i + 1;
        jobs[i].src      = argv[optind + 3 * i];
        jobs[i].input    = argv[optind + 3 * i + 1];
        jobs[i].expected = argv[optind + 3 * i + 2];
        pthread_create(&th[i], NULL, worker, &jobs[i]);
    }
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);

    printf("\n%-3s %-22s %-24s %9s %9s\n", "ID", "SUBMISSION", "VERDICT", "CPU(ms)", "MEM(KB)");
    printf("---------------------------------------------------------------------------\n");
    for (int i = 0; i < n; i++) {
        const char *b = strrchr(jobs[i].src, '/');
        printf("%-3d %-22s %-24s %9.1f %9ld\n", jobs[i].id, b ? b + 1 : jobs[i].src,
               verdict_name(jobs[i].verdict), jobs[i].cpu_ms, jobs[i].mem_kb);
        if (jobs[i].detail[0]) printf("    -> %s\n", jobs[i].detail);
    }
    sem_destroy(&slots);
    rm_rf(g_cfg.workdir);
    free(jobs); free(th);
    return 0;
}
