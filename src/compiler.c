/* Phase 2: fork() + execvp("gcc"). The compiler runs as 'nobody' with limits,
 * because compiling hostile code is itself a risk (#include "/etc/shadow"). */
#include "common.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>

#define NOBODY 65534
#define COMPILE_TIMEOUT_MS 15000.0

int compile_submission(job_t *j, const char *builddir)
{
    char logp[400], progp[400];
    snprintf(logp, sizeof logp, "%s/compile.log", builddir);
    snprintf(progp, sizeof progp, "%s/prog", builddir);

    pid_t pid = fork();
    if (pid < 0) { j->verdict = V_SYSERR; snprintf(j->detail, sizeof j->detail, "fork failed"); return -1; }

    if (pid == 0) {
        int fd = open(logp, O_WRONLY | O_CREAT | O_TRUNC, 0644);   /* as root */
        int nl = open("/dev/null", O_RDONLY);
        if (fd < 0 || nl < 0) _exit(126);
        dup2(nl, 0); dup2(fd, 1); dup2(fd, 2);
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = 10;                 setrlimit(RLIMIT_CPU, &rl);
        rl.rlim_cur = rl.rlim_max = 64UL << 20;         setrlimit(RLIMIT_FSIZE, &rl);
        rl.rlim_cur = rl.rlim_max = 1536UL << 20;       setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = 0;                  setrlimit(RLIMIT_CORE, &rl);
        setenv("TMPDIR", builddir, 1);
        if (chdir(builddir) != 0) _exit(126);
        if (geteuid() == 0) {
            setgroups(0, NULL);
            if (setgid(NOBODY) != 0 || setuid(NOBODY) != 0) _exit(126);
        }
        execlp("gcc", "gcc", "-O2", "-static", "-o", "prog", "sub.c", "-lm", (char *)NULL);
        _exit(127);
    }

    double start = now_ms();
    int status = 0, done = 0;
    while (!done) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) done = 1;
        else if (now_ms() - start > COMPILE_TIMEOUT_MS) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            j->verdict = V_CE;
            snprintf(j->detail, sizeof j->detail, "compilation timed out");
            return -1;
        } else usleep(10000);
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && access(progp, X_OK) == 0)
        return 0;

    j->verdict = V_CE;
    char *log = read_file(logp, NULL);
    if (log) {
        snprintf(j->detail, sizeof j->detail, "%.300s", log);
        for (char *p = j->detail; *p; p++) if (*p == '\n') *p = ' ';
        free(log);
    } else snprintf(j->detail, sizeof j->detail, "compiler failed");
    return -1;
}
