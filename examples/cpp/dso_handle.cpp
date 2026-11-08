// SPDX-License-Identifier: Apache-2.0
// Optional producer-side identity for __cxa_atexit/__cxa_finalize. A native
// executable linker normally supplies this symbol; Go's internal linker does
// not. This example uses one explicit, image-private handle and never unloads.
extern "C" {
__attribute__((visibility("hidden"))) void *__dso_handle = nullptr;
}
