// SPDX-License-Identifier: Apache-2.0
// Isolates supported C++ initialization from destructor/DSO-handle semantics.
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include "platform.h"

namespace {
std::atomic<unsigned> state{0};
void at_exit() {
    constexpr char marker[] = "CXX_ATEXIT_RAN\n";
    (void)write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}
struct Initializer {
    explicit Initializer(unsigned id) {
        if (!bao_example_on_main_thread()) { state = 99; return; }
        if (id == 1) state = 17;
        else if (state == 17) state = bao_example_at_exit<at_exit>() == 0 ? 42 : 98;
    }
    // Deliberately trivial destructor: static_lifetime.cpp tests real ones.
};
Initializer first{1}, second{2};
unsigned local_count;
struct Local { Local() { ++local_count; } };
__attribute__((noinline)) void initialize_local() { static Local local; }
}
extern "C" std::uint64_t bao_example_run() {
    initialize_local(); initialize_local();
    return state == 42 && local_count == 1 ? 42 : 0;
}
