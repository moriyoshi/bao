// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
extern "C" volatile uint64_t bao_windows_crt_state,bao_windows_exit_order;
namespace {
volatile uint64_t tls_drops;
volatile uint64_t local_constructions;
struct Local {
    uint64_t value;
    Local() noexcept:value(42){local_constructions=local_constructions+1;}
    ~Local() noexcept {bao_windows_exit_order=bao_windows_exit_order*10+6;}
};
Local &local(){static Local object;return object;}
struct Global {
    Global() noexcept {if(bao_windows_crt_state==11)bao_windows_crt_state=17;}
    ~Global() noexcept {bao_windows_exit_order=bao_windows_exit_order*10+3;}
} global;
struct PerThread {
    uint64_t value;
    PerThread() noexcept:value(42){}
    ~PerThread() noexcept {tls_drops=tls_drops+1;}
};
thread_local PerThread per_thread;
}
extern "C" uint64_t bao_windows_cpp_tls(){return local().value==42&&local_constructions==1?per_thread.value:0;}
extern "C" uint64_t bao_windows_tls_drops(){return tls_drops;}
