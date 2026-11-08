package pecoff

// OS exports used by the checked static libc++/libunwind profiles. These are
// ordinary installed Windows system libraries, not bundled language DLLs.
func init() {
	for _, name := range []string{"ResumeThread", "ResetEvent", "SetThreadPriority", "CreateEventA", "SetEvent", "SetThreadContext", "GetThreadContext", "SuspendThread", "TlsSetValue", "TlsGetValue", "SetLastError", "SetProcessAffinityMask", "GetProcessAffinityMask", "GetCurrentProcess", "GetThreadPriority", "DuplicateHandle", "GetCurrentThread", "TlsAlloc", "OutputDebugStringA", "OpenProcess", "GetModuleHandleA", "WaitForMultipleObjects", "GetTickCount", "CreateSemaphoreA", "ReleaseSemaphore", "GetModuleHandleExW", "FreeLibrary"} {
		systemImports[name] = "kernel32.dll"
	}
	for _, name := range []string{"__stdio_common_vfprintf", "__stdio_common_vsprintf", "mbsrtowcs", "strdup", "_endthreadex", "longjmp", "_setjmp", "_fpreset", "fputs", "fwrite", "strtoul", "strchr", "strncmp"} {
		systemImports[name] = "ucrtbase.dll"
	}
	systemImports["__msvcrt_assert"] = "ucrtbase.dll"
	for _, name := range []string{"GetSystemTimeAsFileTime", "GetProcAddress", "GetModuleHandleW", "GetLastError", "SwitchToThread", "WaitForSingleObjectEx", "GetThreadId", "InitOnceExecuteOnce", "SleepConditionVariableSRW", "WakeAllConditionVariable", "WakeConditionVariable", "ReleaseSRWLockExclusive", "TryAcquireSRWLockExclusive", "AcquireSRWLockExclusive", "DeleteCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection", "EnterCriticalSection", "InitializeCriticalSection", "RtlCaptureContext", "RtlRestoreContext", "RtlVirtualUnwind", "RtlUnwindEx", "RaiseException"} {
		systemImports[name] = "kernel32.dll"
	}
	for _, name := range []string{"_beginthreadex", "abort", "strlen", "memchr", "__acrt_iob_func", "_aligned_free", "_aligned_malloc", "strcmp", "_assert", "getenv", "fflush", "_unlock_file", "_lock_file", "fputc", "wcrtomb", "mbrtowc", "localeconv", "strnlen", "wcslen", "wcsnlen", "strerror", "_errno", "_setmode", "fileno"} {
		systemImports[name] = "ucrtbase.dll"
	}
}
