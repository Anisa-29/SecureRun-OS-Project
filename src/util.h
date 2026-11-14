#ifndef UTIL_H
#define UTIL_H
#include <stddef.h>
#include <sys/types.h>
char  *read_file(const char *path, size_t *len); /* malloc'd, NUL-terminated */
int    write_file(const char *path, const char *s);
int    copy_file(const char *from, const char *to, mode_t mode);
int    rm_rf(const char *path);
double now_ms(void);
#endif
