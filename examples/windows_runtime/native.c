// SPDX-License-Identifier: Apache-2.0
// COFF imports, real constructor invocation, and native function-table lookup.
#include <stdint.h>
__declspec(dllimport) unsigned long GetCurrentProcessId(void);
__declspec(dllimport) void *RtlLookupFunctionEntry(uint64_t, uint64_t *, void *);
static volatile uint64_t initialized;
#ifdef _MSC_VER
static void initialize(void) { initialized = 17; }
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) void (*const bao_windows_constructor_slot)(void) = initialize;
#else
__attribute__((constructor)) static void initialize(void) { initialized = 17; }
#endif
uint64_t bao_windows_run(uint64_t argument) {
    uint64_t base = 0;
    void *frame = RtlLookupFunctionEntry((uint64_t)&bao_windows_run, &base, (void *)0);
    if (initialized != 17) return 1;
    if (!GetCurrentProcessId()) return 2;
    if (!frame || !base) return 3;
    return argument + 1;
}
