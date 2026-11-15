/* Symbol edit fixture: a component vendoring its own copy of a common
   dependency. Build it with -DCOMPONENT=a -DCOUNTER=1 and -DCOMPONENT=b
   -DCOUNTER=2; without private prefixes the two copies collide. */
#include <string.h>
#define ENTRY2(c) c##_entry
#define ENTRY(c) ENTRY2(c)
int counter = COUNTER;
long vendored_fn(void) { return counter + (long)strlen(""); }
long ENTRY(COMPONENT)(void) { return vendored_fn(); }
