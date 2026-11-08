// SPDX-License-Identifier: Apache-2.0
// Linux/ELF counterpart of the Rust runtime and Darwin C++ lifecycle probes.
#include "../cpp/platform.h"
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include <vector>

// Use glibc's global definition, rather than its weak environ alias, for the
// absolute imported-data pointer exercised by the native linker control too.
extern "C" char **__environ;
extern "C" void *__dso_handle;
extern "C" void __cxa_finalize(void *);

namespace {
std::atomic<unsigned> arguments{0}, initialized{0}, tls_drops{0}, unwind_drops{0};
std::atomic<unsigned> static_drops{0}, static_trace{0}, late_cleanups{0}, errors{0};
std::atomic<bool> reported{false};
pthread_key_t late_key;

// Linux init_array functions receive the native argc/argv/envp. Numeric
// priorities must run before compiler-generated ordinary C++ initialization.
__attribute__((constructor(101))) void first_arguments(int argc, char **argv, char **envp) {
    if (argc > 0 && argv && argv[0] && envp && envp == __environ && bao_example_on_main_thread()) arguments = 17;
}
__attribute__((constructor(102))) void second_arguments() {
    if (arguments == 17) arguments = 42;
}

void report() {
    if (reported.exchange(true)) return;
    const char *message = static_drops == 3 && static_trace == 321 && errors == 0 ?
        "CXX_STATIC_FINALIZERS:321\n" : "FAIL: Linux C++ static destruction\n";
    unsigned size = 0; while (message[size]) ++size;
    (void)write(STDOUT_FILENO, message, size);
}
struct Global {
    unsigned id;
    explicit Global(unsigned value) : id(value) {
        if (!bao_example_on_main_thread() || arguments != 42) ++errors;
        if (id == 1) {
            if (bao_example_at_exit<report>() != 0 || initialized.exchange(17) != 0) ++errors;
        } else if (initialized.exchange(42) != 17) ++errors;
    }
    ~Global() {
        if (tls_drops != 9 || late_cleanups != 8) ++errors;
        static_trace = static_trace * 10 + id;
        ++static_drops;
    }
};
Global first{1}, second{2};
struct Local {
    ~Local() { static_trace = static_trace * 10 + 3; ++static_drops; }
};
__attribute__((noinline)) void local() { static Local value; }

alignas(128) volatile const unsigned char aligned[128] = {42};
const unsigned char bytes[16] = {1};
const unsigned char *volatile interior = bytes + 7;
char ***volatile imported = &__environ;

constinit thread_local std::uint64_t initial = 37;
constinit thread_local std::uint64_t zero = 0;
constinit thread_local bool guard_destroyed = false;
struct alignas(128) Guard {
    unsigned char data[128] = {3};
    ~Guard() {
        if (initial != 38 || zero != 1 || data[0] != 3 || static_drops != 0) ++errors;
        guard_destroyed = true;
        ++tls_drops;
    }
};
constinit thread_local Guard guard;
bool touch(bool register_late) {
    const bool first = initial++ == 37 && zero++ == 0;
    auto *storage = &guard;
    asm volatile("" : "+r"(storage));
    if (!first || reinterpret_cast<std::uintptr_t>(storage) % 128 || storage->data[0] != 3) return false;
    if (register_late && pthread_setspecific(late_key, &initial) != 0) return false;
    return true;
}
void late_cleanup(void *original) {
    // Do not access the destroyed Guard object. Check the still-retained
    // trivial TLS storage and destructor marker from a later pthread callback.
    if (&initial != original || initial != 38 || zero != 1 || !guard_destroyed) ++errors;
    ++late_cleanups;
}

struct Cleanup { ~Cleanup() { ++unwind_drops; } };
struct Failure { unsigned value; };
__attribute__((noinline)) void inner() { Cleanup guard; throw Failure{42}; }
__attribute__((noinline)) void middle() { Cleanup guard; inner(); }
int compare(const void *a, const void *b) {
    const auto left = *static_cast<const std::uint64_t *>(a);
    const auto right = *static_cast<const std::uint64_t *>(b);
    return (left > right) - (left < right);
}
}

extern "C" std::uint64_t bao_example_run() {
    if (initialized != 42 || arguments != 42 || errors != 0 || static_drops != 0) return 1;
    auto *address = aligned;
    asm volatile("" : "+r"(address));
    if (reinterpret_cast<std::uintptr_t>(address) % 128 || address[0] != 42) return 2;
    if (interior - bytes != 7 || imported != &__environ || getpid() <= 0) return 3;
    auto *memory = static_cast<std::uint64_t *>(std::malloc(4 * sizeof(std::uint64_t)));
    if (!memory) return 4;
    memory[0] = 9; memory[1] = 2; memory[2] = 42; memory[3] = 1;
    std::qsort(memory, 4, sizeof(std::uint64_t), compare);
    const bool sorted = memory[0] == 1 && memory[1] == 2 && memory[2] == 9 && memory[3] == 42;
    std::free(memory);
    if (!sorted || pthread_key_create(&late_key, late_cleanup) != 0) return 5;
    local();
    try {
        std::atomic<unsigned> passed{0};
        std::vector<std::thread> workers;
        workers.reserve(8);
        for (unsigned i = 0; i < 8; ++i) workers.emplace_back([&] { if (touch(true)) ++passed; });
        for (auto &worker : workers) worker.join();
        if (passed != 8 || tls_drops != 8 || late_cleanups != 8 || errors != 0 || !touch(false)) return 6;
        try { middle(); return 7; }
        catch (const Failure &failure) { if (failure.value != 42) return 8; }
        if (unwind_drops != 2 || errors != 0) return 9;
    } catch (...) { return 10; }
    return 42;
}

extern "C" std::uint64_t bao_example_check_finalized() {
    return tls_drops == 9 && unwind_drops == 2 && late_cleanups == 8 && errors == 0 && static_drops == 0 ? 42 : 0;
}
extern "C" std::uint64_t bao_example_finalize() {
    if (tls_drops != 9 || unwind_drops != 2 || late_cleanups != 8 || errors != 0) return 0;
    __cxa_finalize(&__dso_handle);
    if (static_drops != 3 || static_trace != 321 || errors != 0) return 0;
    report();
    return 42;
}
extern "C" std::uint64_t bao_example_static_state() {
    return static_drops == 0 ? 42 : static_drops == 3 && static_trace == 321 && errors == 0 ? 43 : 0;
}
