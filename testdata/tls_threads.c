// Native-thread fixture. No Go pointer, Go callback, or C assertion machinery.
#include <mach-o/dyld.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>

typedef struct { uint64_t counter; uint64_t phase; } State;
_Thread_local State bao_tls_state = {41, 0};
_Alignas(64) static _Thread_local uint64_t zeros[8];
static _Atomic int failures;
static _Atomic int arrived;
static _Atomic int release_workers;
static _Atomic int terminators;

extern int bao_tls_register_probe(void);
extern uint64_t bao_rust_tls_next(void);
extern uint64_t bao_rust_tls_zero_next(void);

static void check(int condition) {
    if (!condition)
        atomic_fetch_add(&failures, 1);
}

static void final_a(void *object) {
    check(object == &bao_tls_state);
    check(bao_tls_state.phase == 3);
    check(bao_tls_state.counter == 1041);
    check(zeros[0] != 0);
    bao_tls_state.phase = 4;
    atomic_fetch_add(&terminators, 1);
}

static void final_c(void *object) {
    check(object == &bao_tls_state);
    check(bao_tls_state.phase == 2);
    bao_tls_state.phase = 3;
    atomic_fetch_add(&terminators, 1);
}

static void final_b(void *object) {
    check(object == &bao_tls_state);
    check(bao_tls_state.phase == 1);
    bao_tls_state.phase = 2;
    // Registration during teardown must run before the older final_a.
    _tlv_atexit(final_c, object);
    atomic_fetch_add(&terminators, 1);
}

static void *worker(void *argument) {
    uintptr_t id = (uintptr_t)argument;
    check(bao_tls_register_probe() == 1); // First access allocates the image.
    check(bao_tls_register_probe() == 1); // Reuse must preserve the same ABI.
    check(bao_tls_state.counter == 41);
    check(bao_tls_state.phase == 0);
    check((uintptr_t)zeros % 64 == 0);
    for (int i = 0; i < 8; ++i)
        check(zeros[i] == 0);
    zeros[0] = id + 1;
    atomic_fetch_add(&arrived, 1);
    while (!atomic_load(&release_workers))
        sched_yield();
    for (int i = 0; i < 1000; ++i) {
        check(zeros[0] == id + 1);
        check(++bao_tls_state.counter == 42 + (uint64_t)i);
        check(bao_rust_tls_next() == 42 + (uint64_t)i);
        check(bao_rust_tls_zero_next() == 1 + (uint64_t)i);
    }
    bao_tls_state.phase = 1;
    _tlv_atexit(final_a, &bao_tls_state);
    _tlv_atexit(final_b, &bao_tls_state);
    return 0;
}

int bao_tls_thread_test(void) {
    enum { N = 8 };
    pthread_t threads[N];
    int created = 0;
    for (; created < N; ++created) {
        if (pthread_create(&threads[created], NULL, worker, (void *)(uintptr_t)created) != 0)
            break;
    }
    if (created == N) {
        while (atomic_load(&arrived) != N)
            sched_yield();
    }
    atomic_store(&release_workers, 1);
    for (int i = 0; i < created; ++i)
        check(pthread_join(threads[i], NULL) == 0);
    check(created == N);
    check(atomic_load(&terminators) == N * 3);
    return atomic_load(&failures);
}

uint64_t bao_tls_counter_next(void) {
    return ++bao_tls_state.counter;
}
