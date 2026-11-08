// SPDX-License-Identifier: Apache-2.0
#include "comdat.h"
unsigned comdat_initializations, comdat_finalizations, comdat_drops;
extern "C" uintptr_t bao_windows_comdat_address_b(unsigned);
extern "C" __declspec(dllimport) void *RtlLookupFunctionEntry(uint64_t,uint64_t *,void *);
extern "C" uint64_t bao_windows_comdat_a() { return comdat_run(); }
extern "C" uint64_t bao_windows_comdat_state() {
    return comdat_initializations*100 + comdat_finalizations*10 + comdat_drops;
}
extern "C" uint64_t bao_windows_comdat_check() {
    uintptr_t addresses[] = {(uintptr_t)&comdat_throw, (uintptr_t)&comdat_box,
                            (uintptr_t)&comdat_tls, (uintptr_t)&comdat_local(), (uintptr_t)&comdat_template<1>};
    for (unsigned i=0;i<5;++i) if(addresses[i]!=bao_windows_comdat_address_b(i))return i+1;
    uint64_t base=0;
    if(!RtlLookupFunctionEntry((uint64_t)&comdat_throw,&base,0)||!base)return 6;
    if(!RtlLookupFunctionEntry((uint64_t)&comdat_run,&base,0))return 7;
    return 42;
}
