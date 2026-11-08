// Volatile keeps the constructor observable under -O2. Otherwise the compiler
// can fold the getter to 42 and remove the very initializer this fixture tests.
static volatile unsigned long initialized;

__attribute__((constructor)) static void initialize(void) {
    initialized = 42;
}

unsigned long bao_initialized(void) {
    return initialized;
}
