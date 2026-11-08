// SPDX-License-Identifier: Apache-2.0
// The bounded Darwin C++ profile uses allocation, native threads and TLS,
// while C++ exception propagation remains outside that profile.
#include <atomic>
#include <cstdint>
#include <pthread.h>
#include <string>
#include <vector>
extern "C" void *__dso_handle;
extern "C" void __cxa_finalize(void *);
namespace {
std::atomic<unsigned> initialized{0}, finalized{0}, drops{0};
volatile unsigned input_length=128;
struct Box {
    std::string text;
    std::vector<std::uint64_t> values;
    Box():text(input_length,'x'),values(input_length,42) {++initialized;}
    ~Box(){++finalized;}
};
Box global;
__attribute__((noinline)) Box &local(){static Box box;return box;}
struct alignas(128) Guard {unsigned char value[128]={7};~Guard(){++drops;}};
constinit thread_local Guard guard;
constinit thread_local unsigned visits=0;
bool touch(){auto *p=&guard;asm volatile("":"+r"(p));return visits++==0 && (reinterpret_cast<std::uintptr_t>(p)%128)==0 && p->value[0]==7;}
void *worker(void *result){*static_cast<bool *>(result)=touch();return nullptr;}
}
extern "C" std::uint64_t bao_static_run(){
    if(initialized!=1 || finalized!=0 || global.values.back()!=42)return 1;
    if(local().text.size()!=input_length || initialized!=2)return 2;
    pthread_t threads[8];bool ok[8]={};unsigned started=0;
    for(;started<8;++started)if(pthread_create(&threads[started],nullptr,worker,&ok[started]))break;
    for(unsigned i=0;i<started;++i)if(pthread_join(threads[i],nullptr))return 3;
    if(started!=8 || drops!=8 || !touch())return 4;
    for(bool value:ok)if(!value)return 5;
    return 42;
}
extern "C" std::uint64_t bao_static_check(){return drops==9 && finalized==0 ? 42 : 1;}
extern "C" std::uint64_t bao_static_finalize(){__cxa_finalize(&__dso_handle);return finalized==2 ? 42 : 1;}
extern "C" std::uint64_t bao_static_finalized(){return finalized==2 ? 42 : 1;}
