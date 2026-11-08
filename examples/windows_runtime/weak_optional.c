// SPDX-License-Identifier: Apache-2.0
// GNU COFF null weak fallback. MSVC's /ALTERNATENAME case is in weak.c.
extern unsigned long long bao_windows_missing(void) __attribute__((weak));
unsigned long long bao_windows_optional_run(void) {
    return bao_windows_missing ? bao_windows_missing() : 42;
}
