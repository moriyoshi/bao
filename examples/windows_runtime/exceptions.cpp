// SPDX-License-Identifier: Apache-2.0
// Typed throw/catch and rethrow must unwind real RAII frames within native code.
#include <stdint.h>
extern "C" __declspec(dllimport) void *RtlLookupFunctionEntry(uint64_t,uint64_t *,void *);
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
namespace {
volatile unsigned drops;
struct Failure {unsigned value;};
struct Guard {~Guard() noexcept {drops=drops+1;}};
NOINLINE void leaf(){Guard guard;throw Failure{42};}
NOINLINE void middle(){Guard guard;try {leaf();}catch(const Failure &){throw;}}
}
extern "C" uint64_t bao_windows_exception_run(){
    uint64_t base=0;
    if(!RtlLookupFunctionEntry((uint64_t)&leaf,&base,0)||!base)return 4;
    if(!RtlLookupFunctionEntry((uint64_t)&middle,&base,0))return 5;
    drops=0;
    try{middle();}catch(const Failure &failure){return drops==2?failure.value:1;}catch(...){return 2;}
    return 3;
}
