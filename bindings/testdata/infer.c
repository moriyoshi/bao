// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>
#include <stddef.h>
typedef const volatile int32_t *ConstPointer;
__attribute__((always_inline)) uint64_t infer_inline(uint64_t a, uint32_t b) { return a + b; }
uint64_t infer_caller(uint64_t a) { return infer_inline(a, 42); }
uint64_t infer_mix(int8_t a, uint16_t b, int32_t c, uint64_t d, float x, double y) { return a + b + c + d + (uint64_t)(x+y); }
uintptr_t infer_pointer(ConstPointer p, uintptr_t n) { return p ? (uintptr_t)*p + n : n; }
void infer_void(void) {}
int32_t infer_optimized(int32_t used, double unused) { return used; }
int32_t infer_variadic(int32_t tag, ...) { return tag; }
int32_t infer_callback(int32_t (*function)(int32_t)) { return function(42); }
struct Pair { uint64_t a, b; };
struct Pair infer_aggregate(struct Pair pair) { return pair; }
_Bool infer_bool(_Bool value) { return value; }
