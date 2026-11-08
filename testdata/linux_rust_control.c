// SPDX-License-Identifier: Apache-2.0
// Ordinary native Rust staticlib control. Native CRT/glibc own thread cleanup.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
extern uint64_t bao_example_run(void);
extern uint64_t bao_example_check_finalized(void);
static void *run(void *unused) {
    (void)unused;
    return (void *)(uintptr_t)bao_example_run();
}
int main(void) {
    pthread_t thread;
    void *result;
    if (pthread_create(&thread, 0, run, 0) || pthread_join(thread, &result)) return 1;
    uint64_t finalized = bao_example_check_finalized();
    if ((uintptr_t)result != 42 || finalized != 42) {
        printf("RUST_NATIVE_RESULT:%llu; TLS_FINALIZED:%llu\n",
            (unsigned long long)(uintptr_t)result, (unsigned long long)finalized);
        return 2;
    }
    puts("PASS: native Rust control");
    return 0;
}
