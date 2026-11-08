package pecoff

// OS exports referenced by the checked Rust std Windows profile.
func init() {
	systemImports["TlsFree"] = "kernel32.dll"
	systemImports["InitOnceComplete"] = "kernel32.dll"
	systemImports["InitOnceBeginInitialize"] = "kernel32.dll"
	for _, name := range []string{"WaitOnAddress", "WakeByAddressAll", "WakeByAddressSingle"} {
		systemImports[name] = "api-ms-win-core-synch-l1-2-0.dll"
	}
	for _, name := range []string{"ProcessPrng"} {
		systemImports[name] = "bcryptprimitives.dll"
	}
	for _, name := range []string{"AddVectoredExceptionHandler", "CancelIo", "CompareStringOrdinal", "CopyFileExW", "CreateDirectoryW", "CreateEventW", "CreateFileMappingA", "CreateFileW", "CreateHardLinkW", "CreatePipe", "CreateProcessW", "CreateSymbolicLinkW", "CreateToolhelp32Snapshot", "CreateWaitableTimerExW", "DeleteFileW", "DeleteProcThreadAttributeList", "DeviceIoControl", "ExitProcess", "FindClose", "FindFirstFileExW", "FindNextFileW", "FlushFileBuffers", "FormatMessageW", "FreeEnvironmentStringsW", "GetCommandLineW", "GetConsoleMode", "GetConsoleOutputCP", "GetCurrentDirectoryW", "GetEnvironmentStringsW", "GetEnvironmentVariableW", "GetExitCodeProcess", "GetFileAttributesW", "GetFileInformationByHandle", "GetFileInformationByHandleEx", "GetFileSizeEx", "GetFileType", "GetFinalPathNameByHandleW", "GetFullPathNameW", "GetModuleFileNameW", "GetOverlappedResult", "GetProcessId", "GetStdHandle", "GetSystemDirectoryW", "GetSystemInfo", "GetSystemTimePreciseAsFileTime", "GetTempPathW", "GetWindowsDirectoryW", "HeapReAlloc", "InitializeProcThreadAttributeList", "IsThreadAFiber", "LockFileEx", "MapViewOfFile", "Module32FirstW", "Module32NextW", "MoveFileExW", "MultiByteToWideChar", "ReadConsoleW", "ReadFile", "ReadFileEx", "RemoveDirectoryW", "SetCurrentDirectoryW", "SetEnvironmentVariableW", "SetFileAttributesW", "SetFileInformationByHandle", "SetFilePointerEx", "SetFileTime", "SetHandleInformation", "SetStdHandle", "SetThreadStackGuarantee", "SetWaitableTimer", "SleepEx", "TerminateProcess", "UnlockFile", "UnmapViewOfFile", "UpdateProcThreadAttribute", "WideCharToMultiByte", "WriteConsoleW", "WriteFileEx", "lstrlenW"} {
		systemImports[name] = "kernel32.dll"
	}
	for _, name := range []string{"NtCreateFile", "NtCreateNamedPipeFile", "NtOpenFile", "NtReadFile", "NtSetInformationFile", "NtWriteFile", "RtlNtStatusToDosError"} {
		systemImports[name] = "ntdll.dll"
	}
	for _, name := range []string{"GetUserProfileDirectoryW"} {
		systemImports[name] = "userenv.dll"
	}
	for _, name := range []string{"GetHostNameW", "WSADuplicateSocketW", "WSAGetLastError", "WSARecv", "WSASend", "WSASocketW", "WSAStartup", "accept", "bind", "closesocket", "connect", "freeaddrinfo", "getaddrinfo", "getpeername", "getsockname", "getsockopt", "ioctlsocket", "listen", "recv", "recvfrom", "select", "send", "sendto", "setsockopt", "shutdown"} {
		systemImports[name] = "ws2_32.dll"
	}
}
