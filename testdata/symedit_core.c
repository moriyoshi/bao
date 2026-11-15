/* Symbol edit fixture: stands in for an LTO-lowered libpython.o, which
   defines target, calls it internally and imports strlen. With
   -wrap target -wrap strlen (ld.lld semantics) bao_symedit_wrapped returns
   102*1000000 + 1020*1000 + 1003; unwrapped it returns 2020003. */
#include <stddef.h>
/* Declared here so that freestanding Windows compiles need no C library headers. */
size_t strlen(const char *);
/* GCC targeting PE treats these as unpreemptible and would propagate their
   results across functions, leaving no call to wrap. */
#if defined(__GNUC__) && !defined(__clang__)
#define NOIPA __attribute__((noipa))
#else
#define NOIPA
#endif
NOIPA int target(int x) { return x + 1; }
NOIPA int calls_target(int x) { return target(x) * 10; }
NOIPA size_t measure(const char *s) { return strlen(s); }
long a_entry(void);
long b_entry(void);
long bao_symedit_wrapped(void) { return target(1) * 1000000L + calls_target(1) * 1000L + (long)measure("abc"); }
long bao_symedit_components(void) { return a_entry() * 10 + b_entry(); }
