/* Weakening fixture for bao build: value is weakened in the primary archive
   and a -link-archive may override it; hook is a weakened reference that no
   input defines. bao_symedit_weak returns value() * 10 + hook result. */
static volatile int one = 1;
int value(void) { return one; }
extern int hook(int);
int (*volatile hook_pointer)(int) = hook;
long bao_symedit_weak(void) { return value() * 10 + (hook_pointer ? hook_pointer(1) : 0); }
