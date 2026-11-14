#ifndef COMMON_H
#define COMMON_H
#include <stddef.h>

typedef enum {
    V_PENDING,   /* ran fine, output still needs comparing */
    V_AC, V_WA, V_TLE, V_MLE, V_RLE, V_OLE, V_RE, V_CE, V_SYSERR
} verdict_t;

typedef struct {
    int time_s;        /* CPU time limit (seconds); wall limit = 2x     */
    long mem_mb;       /* memory limit in MB (cgroup memory.max)        */
    int pids_max;      /* max processes inside the sandbox (pids.max)   */
    int workers;       /* semaphore value = concurrent judges           */
    int use_cgroup;    /* 1 = use cgroups v2, 0 = rlimit-only fallback  */
    size_t out_cap;    /* max captured output bytes                     */
    char workdir[128]; /* /tmp/securerun_<pid>                          */
} config_t;

typedef struct {
    int id;
    const char *src, *input, *expected;
    verdict_t verdict;
    double cpu_ms;
    long mem_kb;
    char detail[512];
} job_t;

extern config_t g_cfg;

const char *verdict_name(verdict_t v);
void judge_job(job_t *j);                                      /* judge.c    */
int  compile_submission(job_t *j, const char *builddir);       /* compiler.c */
void run_sandboxed(job_t *j, const char *rootdir, char **out); /* runner.c   */
#endif
