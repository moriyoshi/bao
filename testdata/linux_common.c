/* Common-symbol fixture: a hidden assembler .comm, as OpenSSL's
   x86_64cpuid.s declares OPENSSL_ia32cap_P, and a C tentative definition
   when built with -fcommon. Successive bao_common calls return 173 and 246:
   zero-initialized storage, 16-byte alignment and persistent state. */
__asm__(".hidden OPENSSL_ia32cap_P\n\t.comm OPENSSL_ia32cap_P,40,16");
extern unsigned int OPENSSL_ia32cap_P[10] __attribute__((visibility("hidden")));
int tentative_counter;
long bao_common(void) {
  OPENSSL_ia32cap_P[9] += 7;
  tentative_counter += 3;
  return OPENSSL_ia32cap_P[9] * 10 + tentative_counter + 100 * ((unsigned long)OPENSSL_ia32cap_P % 16 == 0);
}
