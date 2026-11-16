// Relocatable glue combined with darwin_dylib.cpp's dylib (bao build
// -darwin-dylib). It calls and reads the dylib's exports, wraps the
// pthread_create calls of both itself and the dylib (-wrap pthread_create),
// and has thread-local variables of its own beside the dylib's.
#include <pthread.h>

extern int dylib_threads(int n);
extern int dylib_value;

static __thread int depth;
static __thread int seeded = 11;
static int wrapped;

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start)(void *), void *arg) {
    __atomic_fetch_add(&wrapped, 1, __ATOMIC_RELAXED);
    return __real_pthread_create(thread, attr, start, arg);
}

// A data pointer to a dylib export.
static int (*const threads)(int) = dylib_threads;

static void *worker(void *arg) {
    depth += (int)(long)arg;
    return (void *)(long)(depth + seeded);
}

// out: the dylib's thread sum, wrapped thread starts, a new thread's glue
// TLS, this thread's glue TLS, and the dylib's data export.
void glue_check(int n, int *out) {
    depth = 5;
    pthread_t thread;
    void *r;
    pthread_create(&thread, 0, worker, (void *)3L);
    pthread_join(thread, &r);
    out[0] = threads(n);
    out[1] = __atomic_load_n(&wrapped, __ATOMIC_RELAXED);
    out[2] = (int)(long)r;
    out[3] = depth + seeded;
    out[4] = dylib_value;
}
