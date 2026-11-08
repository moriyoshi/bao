// SPDX-License-Identifier: Apache-2.0
// Original Bao TLS support. No Go entry or callback occurs in this runtime.
#include <pthread.h>
#include <crt_externs.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct BaoTerminator {
    void (*function)(void *);
    void *object;
    struct BaoTerminator *next;
} BaoTerminator;

typedef struct {
    void *data;
    BaoTerminator *terminators;
} BaoThread;

static pthread_key_t key;
static const void *initial;
static size_t initial_size;
static size_t initial_alignment;
static _Atomic int ready;
static _Atomic uint64_t live_blocks;
static _Atomic uint64_t destroyed_blocks;

static void destroy_thread(void *arg) {
    BaoThread *thread = arg;
    // POSIX clears the key before calling us. Keep this same image available
    // while terminators access other TLS or register more terminators.
    if (pthread_setspecific(key, thread) != 0)
        abort();
    while (thread->terminators != NULL) {
        BaoTerminator *term = thread->terminators;
        thread->terminators = term->next;
        void (*function)(void *) = term->function;
        void *object = term->object;
        free(term);
        function(object);
    }
    if (pthread_setspecific(key, NULL) != 0)
        abort();
    free(thread->data);
    free(thread);
    atomic_fetch_sub_explicit(&live_blocks, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&destroyed_blocks, 1, memory_order_relaxed);
}

// Called once, before any translated code is entered. The template is native
// static storage in the final executable, never a retained pointer to Go memory.
int bao_tls_configure(const void *bytes, size_t size, size_t alignment) {
    if (atomic_load_explicit(&ready, memory_order_acquire) != 0)
        return -1;
    if (bytes == NULL || size == 0 || alignment < sizeof(void *) ||
        (alignment & (alignment - 1)) != 0)
        return -2;
    int error = pthread_key_create(&key, destroy_thread);
    if (error != 0)
        return error;
    initial = bytes;
    initial_size = size;
    initial_alignment = alignment;
    atomic_store_explicit(&ready, 1, memory_order_release);
    return 0;
}

static BaoThread *current_thread(void) {
    if (atomic_load_explicit(&ready, memory_order_acquire) == 0)
        abort();
    BaoThread *thread = pthread_getspecific(key);
    if (thread == NULL) {
        thread = calloc(1, sizeof(*thread));
        if (thread == NULL)
            abort();
        if (posix_memalign(&thread->data, initial_alignment, initial_size) != 0)
            abort();
        memcpy(thread->data, initial, initial_size);
        if (pthread_setspecific(key, thread) != 0)
            abort();
        atomic_fetch_add_explicit(&live_blocks, 1, memory_order_relaxed);
    }
    return thread;
}

void *bao_tls_lookup(const uintptr_t *descriptor) {
    uintptr_t offset = descriptor[2];
    if (offset >= initial_size)
        abort();
    return (char *)current_thread()->data + offset;
}

// Replacement for the compiler's _tlv_atexit calls in the translated image.
// Keep the LIFO list with its storage so a separate pthread key cannot free
// storage before a terminator reads it. System images keep their own TLV runtime.
void bao_tls_atexit(void (*function)(void *), void *object) {
    BaoThread *thread = current_thread();
    BaoTerminator *term = malloc(sizeof(*term));
    if (term == NULL)
        abort();
    *term = (BaoTerminator){function, object, thread->terminators};
    thread->terminators = term;
}

uint64_t bao_tls_live_blocks(void) {
    return atomic_load_explicit(&live_blocks, memory_order_relaxed);
}

uint64_t bao_tls_destroyed_blocks(void) {
    return atomic_load_explicit(&destroyed_blocks, memory_order_relaxed);
}

// Go exits the process without running C's exit handlers. Applications can
// explicitly finalize the locked startup thread after native teardown. Other
// native threads use the pthread key destructor automatically.
void bao_tls_finalize_current_thread(void) {
    BaoThread *thread = pthread_getspecific(key);
    if (thread != NULL)
        destroy_thread(thread);
}

void bao_tls_patch_pointer(void *place, uintptr_t value) {
    memcpy(place, &value, sizeof(value));
}

void bao_runtime_call_constructor(uintptr_t function) {
    // Covers the argc/argv/environ ABI used by Rust/native initializers in the
    // verified image. Initializers requiring Apple's fourth/fifth arguments
    // need additional support and are not certified by this probe.
    void (*constructor)(int, char **, char **) = (void *)function;
    constructor(*_NSGetArgc(), *_NSGetArgv(), *_NSGetEnviron());
}

uintptr_t bao_runtime_read_pointer(const void *place) {
    uintptr_t value;
    memcpy(&value, place, sizeof(value));
    return value;
}

int bao_runtime_on_main_thread(void) {
    return pthread_main_np();
}
