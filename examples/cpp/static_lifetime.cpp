// SPDX-License-Identifier: Apache-2.0
// Actual compiler-generated global/local static construction and destruction.
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>
#include <unistd.h>
#include "platform.h"

extern "C" void *__dso_handle;
extern "C" void __cxa_finalize(void *);

namespace {
std::atomic<unsigned> initialized{0}, drops{0}, trace{0};
std::atomic<bool> error{false};
std::atomic<bool> reported{false};
// Register this observer before the first C++ destructor, so a normal C++
// executable checks the counters after automatic destruction. Keep I/O out of
// the destructors themselves: they are noexcept and cannot throw in this test.
void report() {
    if (reported.exchange(true)) return;
    const char *message = drops == 3 && trace == 321 && !error ?
        "CXX_STATIC_FINALIZERS:321\n" : "FAIL: C++ static destruction\n";
    unsigned size = 0; while (message[size]) ++size;
    (void)write(STDOUT_FILENO, message, size);
}
struct Global {
    unsigned id;
    explicit Global(unsigned value) : id(value) {
        if (!bao_example_on_main_thread()) error = true;
        if (id == 1) {
            if (bao_example_at_exit<report>() != 0 || initialized.exchange(17) != 0) error = true;
        }
        if (id == 2 && initialized.exchange(42) != 17) error = true;
    }
    ~Global() { trace = trace * 10 + id; ++drops; }
};
Global first{1}, second{2};
struct Local {
    ~Local() { trace = trace * 10 + 3; ++drops; }
};
__attribute__((noinline)) void local() { static Local value; }
}
extern "C" std::uint64_t bao_example_run() {
    if (initialized != 42 || drops != 0 || error) return 1;
    local();
    return 42;
}
extern "C" std::uint64_t bao_example_finalize() {
    __cxa_finalize(&__dso_handle);
    if (drops != 3 || trace != 321 || error) return 0;
    report();
    return 42;
}
extern "C" std::uint64_t bao_example_static_state() {
    return drops == 0 ? 42 : drops == 3 && trace == 321 && !error ? 43 : 0;
}
