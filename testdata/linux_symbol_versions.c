/* Versioned-import fixture: x86_64 pthread_cond_init@GLIBC_2.2.5, the
   compatibility version an unversioned reference binds, rejects a
   CLOCK_MONOTONIC condattr with EINVAL; the default GLIBC_2.3.2 accepts it.
   bao_condtest returns 1 when the condition variable and memcpy work. */
#include <pthread.h>
#include <string.h>
#include <time.h>
long bao_condtest(void) {
  pthread_condattr_t a;
  pthread_cond_t c;
  char src[8] = "abcdefg", dst[8];
  if (pthread_condattr_init(&a) || pthread_condattr_setclock(&a, CLOCK_MONOTONIC)) return -1;
  int r = pthread_cond_init(&c, &a);
  if (r == 0) pthread_cond_destroy(&c);
  memcpy(dst, src, sizeof dst);
  return r * 10 + (dst[6] == 'g');
}
