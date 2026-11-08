#include <stdint.h>

extern void *_NSConcreteStackBlock;
static const void *volatile imported_address = &_NSConcreteStackBlock;
static unsigned char bytes[16];
static unsigned char *volatile interior_pointer = bytes + 7;
_Alignas(128) static unsigned char aligned_data[128];
static volatile unsigned initialized;

__attribute__((constructor)) static void first(int argc, char **argv, char **envp) {
    if (argc > 0 && argv != 0 && argv[0] != 0 && envp != 0)
        initialized = 17;
}

__attribute__((constructor)) static void second(void) {
    initialized = initialized * 2 + 8;
}

uintptr_t bao_import_address(void) { return (uintptr_t)imported_address; }
uintptr_t bao_interior_pointer(void) { return (uintptr_t)interior_pointer; }
uintptr_t bao_bytes_base(void) { return (uintptr_t)bytes; }
uintptr_t bao_aligned_address(void) { return (uintptr_t)aligned_data; }
unsigned bao_initialized_value(void) { return initialized; }
