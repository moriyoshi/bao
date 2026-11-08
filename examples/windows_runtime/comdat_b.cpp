// SPDX-License-Identifier: Apache-2.0
#include "comdat.h"
extern "C" uint64_t bao_windows_comdat_b() { return comdat_run(); }
extern "C" uintptr_t bao_windows_comdat_address_b(unsigned i) {
    uintptr_t addresses[] = {(uintptr_t)&comdat_throw, (uintptr_t)&comdat_box,
                            (uintptr_t)&comdat_tls, (uintptr_t)&comdat_local(), (uintptr_t)&comdat_template<1>};
    return i<5 ? addresses[i] : 0;
}
