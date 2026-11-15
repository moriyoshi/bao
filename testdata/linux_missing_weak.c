/* Missing weak references in the forms zstd and CPython use: a NULL check of
   an optional hook, compiled by x86_64 GCC -fPIC as
   `cmpq $0, ZSTD_trace_compress_begin@GOTPCREL(%rip)` (addend -5), and a
   load of its address. bao_weak returns 21 when both read NULL. */
extern int ZSTD_trace_compress_begin(void) __attribute__((weak));
extern int bao_optional_data __attribute__((weak));
long bao_weak(void) {
  long r = 0;
  if (ZSTD_trace_compress_begin) r += ZSTD_trace_compress_begin();
  else r += 2;
  int *volatile p = &bao_optional_data;
  return r * 10 + (p == 0);
}
