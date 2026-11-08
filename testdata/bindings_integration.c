// SPDX-License-Identifier: Apache-2.0
// Original scalar ABI, debug-inference and scheduler-transition fixture.
#include <stdint.h>
#ifdef _WIN32
__declspec(dllimport) void Sleep(unsigned long milliseconds);
#ifdef _MSC_VER
long _InterlockedExchange(long volatile *, long);
#pragma intrinsic(_InterlockedExchange)
#endif
#else
#include <unistd.h>
static __thread uint64_t bao_binding_tls = 41;

uint64_t bao_scalar_tls_next(void) { return ++bao_binding_tls; }
#endif
int64_t bao_scalar_ints(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e,
                       int32_t f, int32_t g, int32_t h, int32_t i, int32_t j) {
    return a + 2LL*b + 3LL*c + 4LL*d + 5LL*e + 6LL*f + 7LL*g + 8LL*h + 9LL*i + 10LL*j;
}
double bao_scalar_floats(float a, float b, float c, float d, float e,
                         float f, float g, float h, float i, float j,
                         float k, float l, float m, float n, float o,
                         float p, float q, float r) {
    return a + 2.0*b + 3.0*c + 4.0*d + 5.0*e + 6.0*f + 7.0*g + 8.0*h + 9.0*i + 10.0*j
        + 11.0*k + 12.0*l + 13.0*m + 14.0*n + 15.0*o + 16.0*p + 17.0*q + 18.0*r;
}
double bao_scalar_mixed(int8_t a, float b, uint16_t c, double d, int32_t e, float f,
                        uint32_t g, double h, int64_t i, float j, uint64_t k, double l) {
    return a+b+c+d+e+f+g+h+i+j+k+l;
}
int64_t bao_scalar_narrow(int8_t a, int8_t b, int8_t c, int8_t d, int8_t e,
                         int8_t f, int8_t g, int8_t h, int8_t i, int8_t j,
                         int16_t k, uint16_t l, int32_t m, uint32_t n) {
    return a+b+c+d+e+f+g+h+i+j+k+l+m+n;
}
void *bao_scalar_pointer(void *p) { *(uint64_t *)p += 1; return p; }
uint64_t bao_scalar_wait(uint64_t usec, uint32_t *started) {
#ifdef _MSC_VER
    _InterlockedExchange((long volatile *)started, 1);
#else
    __atomic_store_n(started, 1, __ATOMIC_RELEASE);
#endif
#ifdef _WIN32
    Sleep((unsigned long)(usec / 1000));
#else
    usleep((unsigned int)usec);
#endif
    return 42;
}
uint64_t bao_scalar_u32(uint32_t x) { return x; }
