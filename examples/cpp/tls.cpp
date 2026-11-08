// SPDX-License-Identifier: Apache-2.0
// Mirrors Rust's initialized/zero TLS, 128-byte alignment and nine destructors.
#include <atomic>
#include <cstdint>
#include <pthread.h>

namespace {
std::atomic<unsigned> drops{0}, errors{0}, alignment_errors{0};
constinit thread_local std::uint64_t initial = 37;
constinit thread_local std::uint64_t zero = 0;
struct alignas(128) Guard {
    unsigned char value[128] = {3};
#ifndef BAO_CPP_TRIVIAL_TLS
    ~Guard() { if (value[0] != 3 || initial != 38 || zero != 1) ++errors; ++drops; }
#endif
};
constinit thread_local Guard guard;
bool touch() {
    const bool first = initial++ == 37 && zero++ == 0;
    auto *storage = &guard;
    asm volatile("" : "+r"(storage)); // Audit the actual translated TLS address.
    const bool aligned = reinterpret_cast<std::uintptr_t>(storage) % 128 == 0;
    if (!aligned) ++alignment_errors;
    return first && aligned && storage->value[0] == 3;
}
void *worker(void *result) { *static_cast<bool *>(result) = touch(); return nullptr; }
}

extern "C" std::uint64_t bao_example_run() {
    pthread_t threads[8];
    bool passed[8] = {};
    unsigned started = 0;
    for (; started < 8; ++started) if (pthread_create(&threads[started], nullptr, worker, &passed[started])) break;
    for (unsigned i = 0; i < started; ++i) if (pthread_join(threads[i], nullptr)) return 1;
    if (started != 8 || errors != 0) return 2;
    const bool main_ok = touch();
    if (alignment_errors != 0) return 128;
    if (!main_ok) return 2;
    for (bool ok : passed) if (!ok) return 3;
#ifndef BAO_CPP_TRIVIAL_TLS
    if (drops != 8) return 4;
#endif
    return 42;
}
extern "C" std::uint64_t bao_example_check_finalized() {
#ifdef BAO_CPP_TRIVIAL_TLS
    return errors == 0 ? 42 : 0; // Go separately checks nine freed TLS blocks.
#else
    return drops == 9 && errors == 0 ? 42 : 0;
#endif
}
