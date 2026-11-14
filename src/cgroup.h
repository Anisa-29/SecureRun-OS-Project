#ifndef CGROUP_H
#define CGROUP_H
#include <stddef.h>
int  cg_init(void);                                    /* 0 ok, -1 unavailable */
int  cg_create(int id, long mem_mb, int pids_max, char *path, size_t n);
int  cg_join_self(const char *path);                   /* used by the child    */
long cg_kv(const char *path, const char *file, const char *key); /* -1 if none */
void cg_destroy(const char *path);
#endif
