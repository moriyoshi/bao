/* Weakening fixture: a strong definition of value, which overrides the one
   that testdata/symedit_weak.c gets weakened. */
int value(void) { return 2; }
