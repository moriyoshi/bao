// SPDX-License-Identifier: Apache-2.0
// Original Bao TLS support. No Go entry or callback occurs in this runtime.
#include <pthread.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct BaoTerminator {
    void (*function)(void *);
    void *object;
    struct BaoTerminator *next;
} BaoTerminator;

typedef struct BaoThread BaoThread;
typedef struct {
    BaoThread *thread;
} BaoExitHook;

struct BaoThread {
    void *data;
    BaoTerminator *terminators;
    unsigned destructor_pass;
    BaoExitHook *hook;
};

extern char bao_dso_handle;
extern int __cxa_thread_atexit_impl(void (*function)(void *), void *object, void *dso);

static pthread_key_t key;
static const void *initial;
static size_t initial_size;
static size_t initial_alignment;
static _Atomic int ready;
static _Atomic uint64_t live_blocks;
static _Atomic uint64_t destroyed_blocks;

static void run_terminators(BaoThread *thread) {
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
}

static void compiler_tls_exit(void *arg) {
    BaoExitHook *hook = arg;
    BaoThread *thread = hook->thread;
    if (thread != NULL) {
        thread->hook = NULL;
        run_terminators(thread);
    }
    free(hook);
}

static void finalize_thread(BaoThread *thread, int explicit_finalization) {
    run_terminators(thread);
    // glibc runs compiler TLS destructors before pthread key destructors.
    // Rust's pthread cleanup may still read its dropped/initialized TLS state.
    // Retain that state through earlier POSIX key-destructor passes. This is
    // bounded by POSIX's destructor iteration limit; code that resurrects TLS
    // from another key's final allowed pass is outside this runtime's profile.
    if (!explicit_finalization && ++thread->destructor_pass < PTHREAD_DESTRUCTOR_ITERATIONS)
        return;
    if (pthread_setspecific(key, NULL) != 0)
        abort();
    // libc may still own its scheduled callback when the application explicitly
    // finalizes this thread. The tiny hook record survives with a NULL target;
    // its later callback is harmless and frees it. Go process exit skips that
    // callback, so this record then has bounded process lifetime.
    if (thread->hook != NULL) {
        thread->hook->thread = NULL;
        thread->hook = NULL;
    }
    free(thread->data);
    free(thread);
    atomic_fetch_sub_explicit(&live_blocks, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&destroyed_blocks, 1, memory_order_relaxed);
}

static void destroy_thread(void *arg) {
    finalize_thread(arg, 0);
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
        thread->hook = malloc(sizeof(*thread->hook));
        if (thread->hook == NULL)
            abort();
        thread->hook->thread = thread;
        // Delegate only scheduling to glibc. Native image storage and its own
        // LIFO/reentrant destructor list remain owned by Bao. This hook runs
        // before ALL pthread keys, including keys created before this image.
        if (__cxa_thread_atexit_impl(compiler_tls_exit, thread->hook, &bao_dso_handle) != 0)
            abort();
        atomic_fetch_add_explicit(&live_blocks, 1, memory_order_relaxed);
    }
    return thread;
}

void *bao_tls_lookup(const uintptr_t *descriptor) {
    uintptr_t offset = descriptor[1];
    if (offset >= initial_size)
        abort();
    return (char *)current_thread()->data + offset;
}

// Replacement for __cxa_thread_atexit_impl in this translated image.
// Keep the LIFO list with its storage so a separate pthread key cannot free
// storage before a terminator reads it. System images keep their own TLV runtime.
int bao_tls_atexit(void (*function)(void *), void *object, void *dso) {
    (void)dso;
    BaoThread *thread = current_thread();
    BaoTerminator *term = malloc(sizeof(*term));
    if (term == NULL)
        abort();
    *term = (BaoTerminator){function, object, thread->terminators};
    thread->terminators = term;
    return 0;
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
        finalize_thread(thread, 1);
}

void bao_runtime_patch_u32(void *place, uint32_t value) {
    memcpy(place, &value, sizeof(value));
}

void bao_tls_patch_pointer(void *place, uintptr_t value) {
    memcpy(place, &value, sizeof(value));
}

// Retain a native copy: Rust argument initialization keeps these pointers.
extern char **environ;
static int native_argc;
static char **native_argv;
int bao_runtime_allocate_args(int count) {
    if (count < 1 || native_argv != NULL) return -1;
    native_argv = calloc((size_t)count + 1, sizeof(char *));
    if (native_argv == NULL) return -1;
    native_argc = count;
    return 0;
}
int bao_runtime_set_arg(int index, const char *value) {
    if (index < 0 || index >= native_argc || native_argv[index] != NULL) return -1;
    native_argv[index] = strdup(value);
    return native_argv[index] == NULL ? -1 : 0;
}
void bao_runtime_call_constructor(uintptr_t function) {
    void (*constructor)(int, char **, char **) = (void *)function;
    constructor(native_argc, native_argv, environ);
}
uintptr_t bao_runtime_read_pointer(const void *place) {
    uintptr_t value;
    memcpy(&value, place, sizeof(value));
    return value;
}
#if defined(__aarch64__)
uintptr_t bao_tls_lookup_offset(const uintptr_t *descriptor) {
    return (uintptr_t)bao_tls_lookup(descriptor) - (uintptr_t)__builtin_thread_pointer();
}
#endif
char bao_dso_handle;
