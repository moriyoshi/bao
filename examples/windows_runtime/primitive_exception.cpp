// SPDX-License-Identifier: Apache-2.0
// Fundamental GNU RTTI is supplied by the matching C++ runtime DLL.
extern "C" unsigned long long bao_windows_primitive_exception_run() {
    try { throw 42; }
    catch (int value) { return value; }
    catch (...) { return 1; }
}
