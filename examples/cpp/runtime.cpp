// SPDX-License-Identifier: Apache-2.0
// C++ counterpart of rust_runtime: exceptions, RAII, TLS and static lifetime.
#include <CoreFoundation/CoreFoundation.h>
#include <atomic>
#include <cstdint>
#include <pthread.h>
#include <thread>
#include <vector>
#include "platform.h"

namespace {
std::atomic<unsigned> initialized{0}, tls_drops{0}, unwind_drops{0};
std::atomic<unsigned> static_drops{0}, static_trace{0};
std::atomic<bool> lifetime_error{false};

struct Global {
    unsigned id;
    explicit Global(unsigned value) : id(value) {
        if (!bao_example_on_main_thread()) lifetime_error = true;
        if (id == 1 && initialized.exchange(17) != 0) lifetime_error = true;
        if (id == 2 && initialized.exchange(42) != 17) lifetime_error = true;
    }
    ~Global() {
        // TLS teardown must precede explicit global teardown in this example.
        if (tls_drops != 9) lifetime_error = true;
        static_trace = static_trace * 10 + id;
        ++static_drops;
    }
};
Global first{1}, second{2};

struct Local {
    ~Local() { static_trace = static_trace * 10 + 3; ++static_drops; }
};
__attribute__((noinline)) void initialize_local() { static Local local; }

alignas(128) volatile const unsigned char aligned[128] = {5};
const unsigned char bytes[16] = {1};
const void *volatile imported = &kCFAllocatorDefault;
const unsigned char *volatile interior = bytes + 7;

struct alignas(128) Guard {
    unsigned char bytes[128] = {3};
    ~Guard() {
        if (static_drops != 0 || bytes[0] != 3) lifetime_error = true;
        ++tls_drops;
    }
};
constinit thread_local std::uint64_t initial = 37;
constinit thread_local std::uint64_t zero = 0;
constinit thread_local Guard guard;
bool touch() {
    return initial++ == 37 && zero++ == 0 &&
        reinterpret_cast<std::uintptr_t>(&guard) % 128 == 0 && guard.bytes[0] == 3;
}
struct Cleanup { ~Cleanup() { ++unwind_drops; } };
struct Failure { int value; };
__attribute__((noinline)) void inner() { Cleanup cleanup; throw Failure{42}; }
__attribute__((noinline)) void middle() { Cleanup cleanup; inner(); }
}

extern "C" std::uint64_t bao_example_run() {
    if (initialized != 42 || lifetime_error || static_drops != 0) return 1;
    if (reinterpret_cast<std::uintptr_t>(aligned) % 128 != 0 || aligned[0] != 5) return 2;
    if (imported != &kCFAllocatorDefault || interior - bytes != 7) return 3;
    if (CFAbsoluteTimeGetCurrent() <= 0) return 4;
    initialize_local();
    // No exception may cross the Go/C ABI boundary.
    try {
        std::atomic<unsigned> passed{0};
        std::vector<std::thread> threads;
        threads.reserve(8);
        for (unsigned i = 0; i < 8; ++i) threads.emplace_back([&] { if (touch()) ++passed; });
        for (auto &thread : threads) thread.join();
        if (passed != 8 || tls_drops != 8 || !touch()) return 5;
        try { middle(); return 6; }
        catch (const Failure &failure) { if (failure.value != 42) return 7; }
        if (unwind_drops != 2 || lifetime_error) return 8;
    } catch (...) { return 9; }
    return 42;
}

extern "C" std::uint64_t bao_example_check_finalized() {
    return tls_drops == 9 && static_drops == 0 && !lifetime_error ? 42 : 0;
}

// The ordinary native link supplies __dso_handle. The Bao investigation tests
// that requirement explicitly before deciding whether a producer shim is needed.
extern "C" void *__dso_handle;
extern "C" void __cxa_finalize(void *);
extern "C" std::uint64_t bao_example_finalize() {
    __cxa_finalize(&__dso_handle);
    return static_drops == 3 && static_trace == 321 && !lifetime_error ? 42 : 0;
}
