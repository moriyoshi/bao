// SPDX-License-Identifier: Apache-2.0
// C++ scope cleanup and construction without a CRT/exception-runtime dependency.
#include <stdint.h>
extern "C" __declspec(dllimport) unsigned long GetCurrentProcessId(void) noexcept;
namespace {
volatile uint64_t initialized, drops;
struct Initializer { Initializer() noexcept { initialized = 17; } };
Initializer initializer;
struct Guard { ~Guard() noexcept { drops = drops + 1; } };
}
extern "C" uint64_t bao_windows_cpp_run() {
    if (initialized != 17 || drops != 0) return 1;
    { Guard cleanup; if (!GetCurrentProcessId()) return 2; }
    return drops == 1 ? 42 : 3;
}
