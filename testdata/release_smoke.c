// SPDX-License-Identifier: Apache-2.0
#include <stdint.h>

static uint64_t initialized;
static _Thread_local uint64_t value = 37;
__attribute__((constructor)) static void initialize(void) { initialized = 17; }

uint64_t bao_release_check(uint64_t argument) {
    return initialized == 17 && ++value == 38 && argument == 42 ? 42 : 0;
}
