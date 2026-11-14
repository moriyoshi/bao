// Fixture for Bao's DLL input: DllMain, a static constructor, thread_local
// with dynamic initialization across threads, a C++ exception thrown and
// caught inside the DLL, CRT and Win32 imports, and exported data.
#include <windows.h>
#include <cstring>
#include <stdexcept>
#include <string>

static int attached;
static int constructed;
static struct Init {
    Init() { constructed = 42; }
} init_object;
static thread_local int tls_counter;
static thread_local std::string tls_name = "tls";

extern "C" __declspec(dllexport) int dll_value = 7;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) attached++;
    return TRUE;
}

static DWORD WINAPI worker(LPVOID arg) {
    int n = (int)(INT_PTR)arg;
    for (int i = 0; i <= n; i++) tls_counter += i;
    if (tls_name != "tls") return 1000;
    tls_name = "changed";
    return (DWORD)tls_counter;
}

// Each thread starts from its own zero counter and its own initialized name.
extern "C" __declspec(dllexport) int dll_threads(int n) {
    HANDLE threads[16];
    int sum = 0;
    for (int i = 0; i < n; i++) threads[i] = CreateThread(nullptr, 0, worker, (LPVOID)(INT_PTR)i, 0, nullptr);
    for (int i = 0; i < n; i++) {
        DWORD code = 0;
        WaitForSingleObject(threads[i], INFINITE);
        GetExitCodeThread(threads[i], &code);
        CloseHandle(threads[i]);
        sum += (int)code;
    }
    return sum + (tls_name == "tls") + tls_counter;
}

__declspec(noinline) static void thrower(int x) {
    if (x > 0) throw std::runtime_error("thrown in the DLL");
}

extern "C" __declspec(dllexport) int dll_throw(int x) {
    try {
        thrower(x);
    } catch (const std::exception &e) {
        return (int)std::strlen(e.what());
    }
    return -1;
}

extern "C" __declspec(dllexport) int dll_state(void) { return attached * 100 + constructed; }

extern "C" __declspec(dllexport) int dll_format(char *out, int n) {
    std::string s = "v" + std::to_string(dll_value);
    std::strncpy(out, s.c_str(), n);
    return GetCurrentProcessId() != 0;
}
