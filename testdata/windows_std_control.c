// SPDX-License-Identifier: Apache-2.0
// Native-linker control: OS TLS, rather than Bao's private image storage.
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
extern uint64_t bao_windows_std_run(void);
extern uint64_t bao_windows_std_check(void);
extern uint64_t bao_windows_std_counts(uint64_t);
static DWORD WINAPI run(void *out){*(uint64_t *)out=bao_windows_std_run();return 0;}
int main(void){
 uint64_t result=0;HANDLE thread=CreateThread(0,0,run,&result,0,0);
 if(!thread || WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)return 1;
 CloseHandle(thread);
 printf("native result=%llu tls=%llu unwind=%llu lock=%llu failures=%llu fls=%llu\n",(unsigned long long)result,(unsigned long long)bao_windows_std_counts(0),(unsigned long long)bao_windows_std_counts(1),(unsigned long long)bao_windows_std_counts(2),(unsigned long long)bao_windows_std_counts(3),(unsigned long long)bao_windows_std_counts(4));
 if(result!=42 || bao_windows_std_check()!=42 || bao_windows_std_counts(0)!=9 || bao_windows_std_counts(1)!=2 || bao_windows_std_counts(2)!=8 || bao_windows_std_counts(3)!=0 || bao_windows_std_counts(4)!=2)return 2;
 puts("PASS: native Windows Rust std control");return 0;
}
