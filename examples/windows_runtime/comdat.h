// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#ifdef _MSC_VER
#define BAO_NOINLINE __declspec(noinline)
#else
#define BAO_NOINLINE __attribute__((noinline))
#endif
extern unsigned comdat_initializations, comdat_finalizations, comdat_drops;
struct ComdatFailure { uint64_t value; };
struct ComdatGuard { ~ComdatGuard() noexcept { ++comdat_drops; } };
struct ComdatBox {
    ComdatBox() { ++comdat_initializations; }
    ~ComdatBox() noexcept { ++comdat_finalizations; }
    BAO_NOINLINE virtual uint64_t value() { return 42; }
};
inline ComdatBox comdat_box;
inline thread_local unsigned comdat_tls = 42;
template<unsigned N> BAO_NOINLINE inline uint64_t comdat_template(uint64_t value) { return value + N; }
BAO_NOINLINE inline ComdatBox &comdat_local() { static ComdatBox box; return box; }
BAO_NOINLINE inline void comdat_throw() {
    ComdatGuard guard;
    ComdatBox *volatile box = &comdat_local();
    throw ComdatFailure{comdat_template<1>(box->value()-1)};
}
BAO_NOINLINE inline uint64_t comdat_run() {
    try { comdat_throw(); }
    catch (const ComdatFailure &failure) { return failure.value == comdat_tls ? failure.value : 1; }
    catch (...) { return 2; }
    return 3;
}
