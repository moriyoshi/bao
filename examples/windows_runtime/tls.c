// SPDX-License-Identifier: Apache-2.0
// Independent initialized compiler TLS fixture.
#ifdef _MSC_VER
static __declspec(thread) unsigned long long value = 41;
#else
static _Thread_local unsigned long long value = 41;
#endif
unsigned long long bao_windows_tls_run(void) { return ++value; }
