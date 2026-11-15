/* Weakening fixture: a strong definition of value, which overrides the one
   that testdata/symedit_weak.c gets weakened. An archive is searched only for
   unresolved names, and the weak default resolves value, so the build exports
   bao_symedit_strong to pull this member in. */
int value(void) { return 2; }
long bao_symedit_strong(void) { return value(); }
