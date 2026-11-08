// SPDX-License-Identifier: Apache-2.0
#pragma once

#if defined(__APPLE__)
#include <cstdlib>
#include <pthread.h>
inline bool bao_example_on_main_thread() { return pthread_main_np() != 0; }
template<void (*Function)()> int bao_example_at_exit() { return std::atexit(Function); }
#elif defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
extern "C" void *__dso_handle;
extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
inline bool bao_example_on_main_thread() { return syscall(SYS_gettid) == getpid(); }
// glibc's atexit wrapper is supplied by libc_nonshared.a at an ordinary native
// link. Use its public C++ ABI primitive directly for relocatable Go inputs.
template<void (*Function)()> int bao_example_at_exit() {
    return __cxa_atexit([](void *) { Function(); }, nullptr, &__dso_handle);
}
#else
#error These lifecycle probes require Darwin or Linux.
#endif
