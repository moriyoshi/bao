// Fixture for Bao's dylib input: an initializer, a static constructor,
// thread_local with dynamic initialization and an address initializer across
// threads, a C++ exception thrown and caught inside the dylib, imports from
// libSystem, from libz (a separate library) and from libdep through @rpath,
// and exported data.
#include <pthread.h>
#include <zlib.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>
#include <string>

static int attached;
static int constructed;
static struct Init {
    Init() { constructed = 42; }
} init_object;
static thread_local int tls_counter;
static thread_local std::string tls_name = "tls";
static const char tls_text[] = "addr";
static thread_local const char *tls_pointer = tls_text; // fixed-up TLS initializer

extern "C" __attribute__((visibility("default"))) int dylib_value = 7;
extern "C" int dylib_dep_value(void); // @rpath/libdep.dylib

__attribute__((constructor)) static void attach() { attached++; }

static void *worker(void *arg) {
    int n = (int)(long)arg;
    for (int i = 0; i <= n; i++) tls_counter += i;
    if (tls_name != "tls" || tls_pointer != tls_text) return (void *)1000L;
    tls_name = "changed";
    return (void *)(long)tls_counter;
}

// Each thread starts from its own zero counter and its own initialized name.
extern "C" __attribute__((visibility("default"))) int dylib_threads(int n) {
    pthread_t threads[16];
    int sum = 0;
    for (int i = 0; i < n; i++) pthread_create(&threads[i], nullptr, worker, (void *)(long)i);
    for (int i = 0; i < n; i++) {
        void *r;
        pthread_join(threads[i], &r);
        sum += (int)(long)r;
    }
    return sum + (tls_name == "tls") + tls_counter;
}

__attribute__((noinline)) static void thrower(int x) {
    if (x > 0) throw std::runtime_error("thrown in the DLL");
}

extern "C" __attribute__((visibility("default"))) int dylib_throw(int x) {
    try {
        thrower(x);
    } catch (const std::exception &e) {
        return (int)std::strlen(e.what());
    }
    return -1;
}

extern "C" __attribute__((visibility("default"))) int dylib_state(void) { return attached * 100 + constructed; }

extern "C" __attribute__((visibility("default"))) int dylib_format(char *out, int n) {
    std::string s = "v" + std::to_string(dylib_value);
    std::strncpy(out, s.c_str(), n);
    return getpid() != 0 && zlibVersion()[0] != 0 && dylib_dep_value() == 5;
}
