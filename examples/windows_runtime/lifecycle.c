// SPDX-License-Identifier: Apache-2.0
// Real CRT tables, allocation, compiler TLS and OS-created thread teardown.
#include <stdint.h>
#ifdef _MSC_VER
#define TLS __declspec(thread)
#define ALIGNED __declspec(align(128))
#define TABLE(section_name) __declspec(allocate(section_name))
#pragma section(".CRT$XIU",read)
#pragma section(".CRT$XPU",read)
#pragma section(".CRT$XTU",read)
#pragma section(".CRT$XLB",read)
#else
#define TLS _Thread_local
#define ALIGNED __attribute__((aligned(128)))
#define TABLE(section_name) __attribute__((section(section_name),used))
#endif
#define DLL __declspec(dllimport)
DLL void *malloc(uint64_t);
DLL void free(void *);
DLL void *CreateThread(void *,uint64_t,unsigned long (*)(void *),void *,unsigned long,unsigned long *);
DLL unsigned long WaitForSingleObject(void *,unsigned long);
DLL int CloseHandle(void *);
extern int atexit(void (*)(void));
extern uint64_t bao_windows_cpp_tls(void);
volatile uint64_t bao_windows_crt_state, bao_windows_exit_order;
static volatile uint64_t attaches, detaches;
static volatile uint64_t process_attaches,process_detaches;
static TLS volatile uint64_t initialized_tls=41, zero_tls;
static ALIGNED TLS unsigned char aligned_tls[128]={7};
static int c_initialize(void) {bao_windows_crt_state=11;return 0;}
static void pre_terminate(void) {bao_windows_exit_order=bao_windows_exit_order*10+4;}
static void terminate(void) {bao_windows_exit_order=bao_windows_exit_order*10+5;}
static void tls_callback(void *module,unsigned long reason,void *reserved) {
    (void)module;(void)reserved;
    if(reason==2)attaches=attaches+1;
    if(reason==3)detaches=detaches+1;
    if(reason==1)process_attaches=process_attaches+1;
    if(reason==0)process_detaches=process_detaches+1;
}
TABLE(".CRT$XIU") int (*bao_windows_c_initializer)(void)=c_initialize;
TABLE(".CRT$XPU") void (*bao_windows_pre_terminator)(void)=pre_terminate;
TABLE(".CRT$XTU") void (*bao_windows_terminator)(void)=terminate;
TABLE(".CRT$XLB") void (*bao_windows_tls_notifier)(void *,unsigned long,void *)=tls_callback;
static void exit_one(void){bao_windows_exit_order=bao_windows_exit_order*10+1;}
static void exit_two(void){bao_windows_exit_order=bao_windows_exit_order*10+2;}
static uint64_t tls_value(void){if((uint64_t)aligned_tls%128||aligned_tls[0]!=7)return 0;return ++initialized_tls+zero_tls++;}
static unsigned long worker(void *result){*(uint64_t *)result=tls_value()+bao_windows_cpp_tls();return 0;}
uint64_t bao_windows_lifecycle_run(void) {
    if(bao_windows_crt_state!=17)return 1;
    uint64_t *p=malloc(16);if(!p)return 2;*p=42;if(*p!=42)return 3;free(p);
    if(atexit(exit_one)||atexit(exit_two))return 4;
    if(tls_value()!=42||tls_value()!=44||bao_windows_cpp_tls()!=42)return 5;
    for(unsigned i=0;i<8;i++) {
        uint64_t result=0;
        void *thread=CreateThread(0,0,worker,&result,0,0);
        if(!thread)return 6;
        unsigned long wait=WaitForSingleObject(thread,30000);CloseHandle(thread);
        if(wait||result!=84)return 7;
    }
    return attaches==9&&detaches==8?42:8;
}
uint64_t bao_windows_lifecycle_state(void){return bao_windows_exit_order;}
uint64_t bao_windows_tls_detaches(void){return detaches;}
uint64_t bao_windows_process_events(void){return process_attaches*10+process_detaches;}
// Return the actual address for a Go-side check the C optimizer cannot fold.
uint64_t bao_windows_tls_address(void){return (uint64_t)aligned_tls;}
