// SPDX-License-Identifier: Apache-2.0
// Exception stays entirely within C++; two intermediate RAII cleanups run.
#include <cstdint>
namespace {
unsigned drops;
struct Guard { ~Guard() { ++drops; } };
struct Failure { unsigned value; };
__attribute__((noinline)) void inner() { Guard guard; throw Failure{42}; }
__attribute__((noinline)) void middle() { Guard guard; inner(); }
}
extern "C" std::uint64_t bao_example_run() {
    try { middle(); return 1; }
    catch (const Failure &failure) { return failure.value == 42 && drops == 2 ? 42 : 2; }
    catch (...) { return 3; }
}
