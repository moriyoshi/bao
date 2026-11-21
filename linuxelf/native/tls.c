// SPDX-License-Identifier: Apache-2.0
// Original Bao TLS support. No Go entry or callback occurs in this runtime.
#include <pthread.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct BaoTerminator {
    void (*function)(void *);
    void *object;
    struct BaoTerminator *next;
} BaoTerminator;

typedef struct BaoThread BaoThread;
typedef struct {
    BaoThread *thread;
} BaoExitHook;

// The thunks' fast paths read tp at offset 0 and data at offset 8.
struct BaoThread {
    _Atomic uintptr_t tp; // the owning thread's pointer, or 0 once released
    void *data;
    BaoTerminator *terminators;
    unsigned destructor_pass;
    BaoExitHook *hook;
    BaoThread *next_free;
};

// Each thread's record is published in a table indexed by a hash of its
// thread pointer, so that lookups need neither a call nor
// pthread_getspecific. An entry is trusted only when the record's tp is the
// caller's own thread pointer, which no other live thread shares. Records
// are recycled, never freed, so a stale entry always points at a record
// whose tp is 0 or another thread's. The thunks compute the same index.
#define BAO_TLS_CACHE_BITS 12
BaoThread *_Atomic bao_tls_cache[1u << BAO_TLS_CACHE_BITS];

static inline uintptr_t thread_pointer(void) {
#if defined(__x86_64__)
    uintptr_t tp;
    __asm__("movq %%fs:0, %0" : "=r"(tp));
    return tp;
#elif defined(__powerpc64__)
    uintptr_t tp;
    __asm__("mr %0, 13" : "=r"(tp));
    return tp;
#else
    return (uintptr_t)__builtin_thread_pointer();
#endif
}

static inline size_t cache_index(uintptr_t tp) {
    return ((tp >> 12) ^ (tp >> 23)) & ((1u << BAO_TLS_CACHE_BITS) - 1);
}

static inline BaoThread *cached_thread(void) {
    uintptr_t tp = thread_pointer();
    BaoThread *thread = atomic_load_explicit(&bao_tls_cache[cache_index(tp)], memory_order_acquire);
    if (thread != NULL && atomic_load_explicit(&thread->tp, memory_order_relaxed) == tp)
        return thread;
    return NULL;
}

static void publish(BaoThread *thread) {
    atomic_store_explicit(&bao_tls_cache[cache_index(thread->tp)], thread, memory_order_release);
}

static pthread_mutex_t free_lock = PTHREAD_MUTEX_INITIALIZER;
static BaoThread *free_records;

static BaoThread *new_record(void) {
    pthread_mutex_lock(&free_lock);
    BaoThread *thread = free_records;
    if (thread != NULL)
        free_records = thread->next_free;
    pthread_mutex_unlock(&free_lock);
    if (thread == NULL) {
        thread = calloc(1, sizeof(*thread));
        if (thread == NULL)
            abort();
    }
    thread->data = NULL;
    thread->terminators = NULL;
    thread->destructor_pass = 0;
    thread->hook = NULL;
    thread->next_free = NULL;
    atomic_store_explicit(&thread->tp, thread_pointer(), memory_order_relaxed);
    return thread;
}

// release unpublishes a record and returns it for reuse. Its tp becomes 0
// before its storage goes, so no lookup can match it afterwards.
static void release(BaoThread *thread) {
    BaoThread *expected = thread;
    atomic_compare_exchange_strong_explicit(&bao_tls_cache[cache_index(thread->tp)], &expected, NULL, memory_order_relaxed, memory_order_relaxed);
    atomic_store_explicit(&thread->tp, 0, memory_order_release);
    pthread_mutex_lock(&free_lock);
    thread->next_free = free_records;
    free_records = thread;
    pthread_mutex_unlock(&free_lock);
}

// A forked child keeps only the forking thread, and glibc may hand a dead
// thread's TCB, and so its thread pointer, to a new thread. Unpublish every
// other record so that no new thread can match one. Their storage is
// abandoned, as before the cache existed.
static void fork_prepare(void) {
    pthread_mutex_lock(&free_lock);
}

static void fork_parent(void) {
    pthread_mutex_unlock(&free_lock);
}

static void fork_child(void) {
    uintptr_t tp = thread_pointer();
    for (size_t i = 0; i < sizeof(bao_tls_cache) / sizeof(bao_tls_cache[0]); i++) {
        BaoThread *thread = atomic_load_explicit(&bao_tls_cache[i], memory_order_relaxed);
        if (thread != NULL && atomic_load_explicit(&thread->tp, memory_order_relaxed) != tp) {
            atomic_store_explicit(&bao_tls_cache[i], NULL, memory_order_relaxed);
            atomic_store_explicit(&thread->tp, 0, memory_order_relaxed);
        }
    }
    pthread_mutex_unlock(&free_lock);
}

extern char bao_dso_handle;
extern int __cxa_thread_atexit_impl(void (*function)(void *), void *object, void *dso);
// pthread_atfork itself lives in libc_nonshared.a; this is what it calls.
extern int __register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void), void *dso);

static pthread_key_t key;
static const void *initial;
static size_t initial_size;
static size_t initial_alignment;
static _Atomic int ready;
// Set by bao_tls_use_static before translated code first runs: every
// thread's block is then glibc static TLS at this thread-pointer offset.
static int static_tls;
static intptr_t static_offset;
static _Atomic uint64_t live_blocks;
static _Atomic uint64_t destroyed_blocks;

// A value read back from the key must be the calling thread's own record.
// Bao stores nothing else there, and a record's tp is its owner's thread
// pointer until release, which happens only after the key is cleared. Any
// other value was stored by foreign code, typically pthread_setspecific
// through a pthread_key_t that was never created: a zeroed one is key 0,
// often this key. The cache would hide that until an eviction, and the
// foreign object would then be used as a record.
static _Noreturn void foreign_key_value(void) {
    static const char message[] = "bao: the TLS pthread key holds a value that is not this thread's record; other code stored through Bao's key, for example pthread_setspecific with a key that pthread_key_create never set\n";
    ssize_t written = write(2, message, sizeof(message) - 1);
    (void)written;
    abort();
}

static BaoThread *owned(BaoThread *thread) {
    if (atomic_load_explicit(&thread->tp, memory_order_relaxed) != thread_pointer())
        foreign_key_value();
    return thread;
}

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
        // run_terminators stores the record again, which would hide this.
        if (pthread_getspecific(key) != thread)
            foreign_key_value();
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
    void *data = thread->data;
    release(thread);
    // A static block lives as long as its thread. Restore the template so
    // that, as with a new block, later accesses see initial values.
    if (static_tls)
        memcpy(data, initial, initial_size);
    else
        free(data);
    atomic_fetch_sub_explicit(&live_blocks, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&destroyed_blocks, 1, memory_order_relaxed);
}

static void destroy_thread(void *arg) {
    finalize_thread(owned(arg), 0);
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
    error = __register_atfork(fork_prepare, fork_parent, fork_child, &bao_dso_handle);
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
        thread = new_record();
        if (static_tls) {
            thread->data = (char *)thread_pointer() + static_offset;
        } else {
            if (posix_memalign(&thread->data, initial_alignment, initial_size) != 0)
                abort();
            memcpy(thread->data, initial, initial_size);
        }
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
    } else {
        owned(thread);
    }
    publish(thread);
    return thread;
}

void *bao_tls_lookup(const uintptr_t *descriptor) {
    uintptr_t offset = descriptor[1];
    if (offset >= initial_size)
        abort();
    if (static_tls)
        return (char *)thread_pointer() + static_offset + offset;
    BaoThread *thread = cached_thread();
    if (thread == NULL)
        thread = current_thread();
    return (char *)thread->data + offset;
}

#if defined(__aarch64__) || defined(__x86_64__)
extern void bao_tls_thunk(void);
extern void bao_tls_static_resolver(void);
#endif

// Called once by the generated package after it has dlopened a module whose
// PT_TLS image is this image's fixed-up template and that glibc placed in
// static TLS at offset from every thread pointer, and before translated code
// first runs. Descriptors then resolve with a single load; no Bao block is
// allocated. Nothing changes unless every descriptor checks out.
int bao_tls_use_static(intptr_t offset, uintptr_t *const *descriptors, size_t count) {
    if (atomic_load_explicit(&ready, memory_order_acquire) == 0 || static_tls)
        return -1;
#if defined(__aarch64__) || defined(__x86_64__)
    for (size_t i = 0; i < count; i++) {
        if (descriptors[i][0] != (uintptr_t)bao_tls_thunk || descriptors[i][1] >= initial_size)
            return -2;
    }
    for (size_t i = 0; i < count; i++) {
        descriptors[i][1] += (uintptr_t)offset;
        descriptors[i][0] = (uintptr_t)bao_tls_static_resolver;
    }
#else
    if (count != 0)
        return -3;
#endif
    static_offset = offset;
    static_tls = 1;
    return 0;
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
        finalize_thread(owned(thread), 1);
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
