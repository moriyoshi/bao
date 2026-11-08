// SPDX-License-Identifier: Apache-2.0
// Observe ELF fini table priority and reverse entry order. The Go consumer must
// explicitly finalize only after all native threads and caller TLS are done.
#include <cstdint>
static std::uint64_t order;
static void one() { order = order * 10 + 1; }
static void two() { order = order * 10 + 2; }
static void three() { order = order * 10 + 3; }
using Finalizer = void (*)();
__attribute__((used, section(".fini_array.00101")))
static Finalizer first[] = {one};
__attribute__((used, section(".fini_array.00102")))
static Finalizer last[] = {two, three};
extern "C" std::uint64_t bao_static_fini_state() { return order; }
