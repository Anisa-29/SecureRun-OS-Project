/* Orchestrates one submission: dirs -> compile -> sandbox run -> compare -> cleanup. */
#include "common.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* Strip trailing spaces/CR per line and trailing blank lines. */
static char *normalize(const char *s)
{
    size_t n = strlen(s), k = 0, i = 0;
    char *o = malloc(n + 2);
    while (i < n) {
        size_t j = i;
        while (j < n && s[j] != '\n') j++;
        size_t e = j;
        while (e > i && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) e--;
        memcpy(o + k, s + i, e - i);
        k += e - i;
        o[k++] = '\n';
        i = j + 1;
    }
    while (k > 0 && o[k - 1] == '\n') k--;
    o[k] = 0;
    return o;
}

static void compare(job_t *j, const char *actual)
{
    char *exp = read_file(j->expected, NULL);
    if (!exp) { j->verdict = V_SYSERR; snprintf(j->detail, sizeof j->detail, "cannot read expected file"); return; }
    char *a = normalize(actual), *e = normalize(exp);
    j->verdict = strcmp(a, e) == 0 ? V_AC : V_WA;
    if (j->verdict == V_WA) snprintf(j->detail, sizeof j->detail, "output differs from expected");
    free(a); free(e); free(exp);
}

void judge_job(job_t *j)
{
    char jobdir[300], builddir[320], rootdir[320], p1[360], p2[360];
    snprintf(jobdir, sizeof jobdir, "%s/job%d", g_cfg.workdir, j->id);
    snprintf(builddir, sizeof builddir, "%s/build", jobdir);
    snprintf(rootdir, sizeof rootdir, "%s/root", jobdir);

    mkdir(jobdir, 0755);  chmod(jobdir, 0755);
    mkdir(builddir, 0755); chmod(builddir, 0755);
    mkdir(rootdir, 0755);  chmod(rootdir, 0755);
    if (geteuid() == 0) { if (chown(builddir, 65534, 65534) != 0) { /* best effort */ } }

    snprintf(p1, sizeof p1, "%s/sub.c", builddir);
    if (copy_file(j->src, p1, 0644) != 0) {
        j->verdict = V_SYSERR;
        snprintf(j->detail, sizeof j->detail, "cannot read submission %s", j->src);
        goto done;
    }
    if (compile_submission(j, builddir) != 0) goto done;

    snprintf(p1, sizeof p1, "%s/prog", builddir);
    snprintf(p2, sizeof p2, "%s/prog", rootdir);
    if (copy_file(p1, p2, 0555) != 0) {
        j->verdict = V_SYSERR;
        snprintf(j->detail, sizeof j->detail, "cannot install binary in jail");
        goto done;
    }

    char *out = NULL;
    run_sandboxed(j, rootdir, &out);
    if (j->verdict == V_PENDING && out) compare(j, out);
    free(out);

done:
    rm_rf(jobdir);
}
