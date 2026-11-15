/* Symbol edit fixture: a component vendoring its own copy of a common
   dependency. Build it with -DCOMPONENT=a -DCOUNTER=1 and -DCOMPONENT=b
   -DCOUNTER=2; without private prefixes the two copies collide. */
#include <stddef.h>
/* Declared here so that freestanding Windows compiles need no C library headers. */
size_t strlen(const char *);
#define ENTRY2(c) c##_entry
#define ENTRY(c) ENTRY2(c)
int counter = COUNTER;
/* Read through a volatile pointer so that no compiler folds the call. */
static const char *volatile empty = "";
long vendored_fn(void) { return counter + (long)strlen(empty); }
long ENTRY(COMPONENT)(void) { return vendored_fn(); }
