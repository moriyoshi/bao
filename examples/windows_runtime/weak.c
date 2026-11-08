// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
uint64_t bao_windows_fallback(void){return 42;}
#ifdef _MSC_VER
#pragma comment(linker,"/alternatename:bao_windows_optional=bao_windows_fallback")
extern uint64_t bao_windows_optional(void);
#else
uint64_t bao_windows_optional(void) __attribute__((weak,alias("bao_windows_fallback")));
#endif
uint64_t bao_windows_weak_run(void){return bao_windows_optional();}
