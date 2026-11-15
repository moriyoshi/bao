/* Symbol edit fixture: wrapper glue for testdata/symedit_core.c. */
#include <stddef.h>
/* Declared here so that freestanding Windows compiles need no C library headers. */
size_t strlen(const char *);
int __real_target(int);
int __wrap_target(int x) { return __real_target(x) + 100; }
size_t __real_strlen(const char *);
size_t __wrap_strlen(const char *s) { return __real_strlen(s) + 1000; }
