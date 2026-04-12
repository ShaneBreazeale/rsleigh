//! Win32 API function signatures.

use crate::signatures::*;

pub static WIN32_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // Memory
    fn VirtualAlloc(lpAddress: LpVoid, dwSize: SizeT, flAllocationType: DWord, flProtect: DWord) -> LpVoid;
    fn VirtualFree(lpAddress: LpVoid, dwSize: SizeT, dwFreeType: DWord) -> Bool;
    fn VirtualProtect(lpAddress: LpVoid, dwSize: SizeT, flNewProtect: DWord, lpflOldProtect: VoidPtr) -> Bool;
    fn HeapAlloc(hHeap: Handle, dwFlags: DWord, dwBytes: SizeT) -> LpVoid;
    fn HeapFree(hHeap: Handle, dwFlags: DWord, lpMem: LpVoid) -> Bool;

    // File I/O
    fn CreateFileA(lpFileName: ConstCharPtr, dwDesiredAccess: DWord, dwShareMode: DWord, lpSecurityAttributes: VoidPtr, dwCreationDisposition: DWord, dwFlagsAndAttributes: DWord, hTemplateFile: Handle) -> Handle;
    fn CreateFileW(lpFileName: ConstWCharPtr, dwDesiredAccess: DWord, dwShareMode: DWord, lpSecurityAttributes: VoidPtr, dwCreationDisposition: DWord, dwFlagsAndAttributes: DWord, hTemplateFile: Handle) -> Handle;
    fn ReadFile(hFile: Handle, lpBuffer: LpVoid, nNumberOfBytesToRead: DWord, lpNumberOfBytesRead: VoidPtr, lpOverlapped: VoidPtr) -> Bool;
    fn WriteFile(hFile: Handle, lpBuffer: ConstVoidPtr, nNumberOfBytesToWrite: DWord, lpNumberOfBytesWritten: VoidPtr, lpOverlapped: VoidPtr) -> Bool;
    fn CloseHandle(hObject: Handle) -> Bool;

    // Module
    fn GetProcAddress(hModule: HModule, lpProcName: ConstCharPtr) -> VoidPtr;
    fn LoadLibraryA(lpLibFileName: ConstCharPtr) -> HModule;
    fn LoadLibraryW(lpLibFileName: ConstWCharPtr) -> HModule;
    fn GetModuleHandleA(lpModuleName: ConstCharPtr) -> HModule;
    fn GetModuleHandleW(lpModuleName: ConstWCharPtr) -> HModule;

    // Process
    fn CreateProcessA(lpApplicationName: ConstCharPtr, lpCommandLine: CharPtr, lpProcessAttributes: VoidPtr, lpThreadAttributes: VoidPtr, bInheritHandles: Bool, dwCreationFlags: DWord, lpEnvironment: VoidPtr, lpCurrentDirectory: ConstCharPtr, lpStartupInfo: VoidPtr, lpProcessInformation: VoidPtr) -> Bool;
    fn CreateProcessW(lpApplicationName: ConstWCharPtr, lpCommandLine: WCharPtr, lpProcessAttributes: VoidPtr, lpThreadAttributes: VoidPtr, bInheritHandles: Bool, dwCreationFlags: DWord, lpEnvironment: VoidPtr, lpCurrentDirectory: ConstWCharPtr, lpStartupInfo: VoidPtr, lpProcessInformation: VoidPtr) -> Bool;
    fn CreateRemoteThread(hProcess: Handle, lpThreadAttributes: VoidPtr, dwStackSize: SizeT, lpStartAddress: VoidPtr, lpParameter: LpVoid, dwCreationFlags: DWord, lpThreadId: VoidPtr) -> Handle;
    fn WriteProcessMemory(hProcess: Handle, lpBaseAddress: LpVoid, lpBuffer: ConstVoidPtr, nSize: SizeT, lpNumberOfBytesWritten: VoidPtr) -> Bool;

    // Error
    fn GetLastError() -> DWord;
    fn SetLastError(dwErrCode: DWord);

    // Registry
    fn RegOpenKeyExA(hKey: HKey, lpSubKey: LpCStr, ulOptions: DWord, samDesired: RegSam, phkResult: PhKey) -> LStatus;
    fn RegSetValueExA(hKey: HKey, lpValueName: LpCStr, Reserved: DWord, dwType: DWord, lpData: ConstVoidPtr, cbData: DWord) -> LStatus;

    // === Ghidra-imported: additional Win32 APIs (from windows_vs12_64.gdt) ===
    fn ControlService(hService: ScHandle, dwControl: DWord, lpServiceStatus: VoidPtr) -> Int;
    fn CopyFileA(lpExistingFileName: ConstCharPtr, lpNewFileName: ConstCharPtr, bFailIfExists: Int) -> Int;
    fn CreateEventA(lpEventAttributes: VoidPtr, bManualReset: Int, bInitialState: Int, lpName: ConstCharPtr) -> Handle;
    fn CreateEventW(lpEventAttributes: VoidPtr, bManualReset: Int, bInitialState: Int, lpName: ConstWCharPtr) -> Handle;
    fn CreateMutexA(lpMutexAttributes: VoidPtr, bInitialOwner: Int, lpName: ConstCharPtr) -> Handle;
    fn CreateMutexW(lpMutexAttributes: VoidPtr, bInitialOwner: Int, lpName: ConstWCharPtr) -> Handle;
    fn CreateServiceA(hSCManager: ScHandle, lpServiceName: ConstCharPtr, lpDisplayName: ConstCharPtr, dwDesiredAccess: DWord, dwServiceType: DWord, dwStartType: DWord, dwErrorControl: DWord, lpBinaryPathName: ConstCharPtr, lpLoadOrderGroup: ConstCharPtr, lpdwTagId: VoidPtr, lpDependencies: ConstCharPtr, lpServiceStartName: ConstCharPtr, lpPassword: LpCStr) -> ScHandle;
    fn CreateServiceW(hSCManager: ScHandle, lpServiceName: ConstWCharPtr, lpDisplayName: ConstWCharPtr, dwDesiredAccess: DWord, dwServiceType: DWord, dwStartType: DWord, dwErrorControl: DWord, lpBinaryPathName: ConstWCharPtr, lpLoadOrderGroup: ConstWCharPtr, lpdwTagId: VoidPtr, lpDependencies: ConstWCharPtr, lpServiceStartName: ConstWCharPtr, lpPassword: LpCWStr) -> ScHandle;
    fn CreateThread(lpThreadAttributes: VoidPtr, dwStackSize: SizeT, lpStartAddress: VoidPtr, lpParameter: VoidPtr, dwCreationFlags: DWord, lpThreadId: VoidPtr) -> Handle;
    fn CryptAcquireContextA(phProv: VoidPtr, szContainer: ConstCharPtr, szProvider: ConstCharPtr, dwProvType: DWord, dwFlags: DWord) -> Int;
    fn CryptGenRandom(hProv: Handle, dwLen: DWord, pbBuffer: VoidPtr) -> Int;
    fn CryptReleaseContext(hProv: Handle, dwFlags: DWord) -> Int;
    fn DeleteCriticalSection(lpCriticalSection: VoidPtr);
    fn DeleteFileA(lpFileName: ConstCharPtr) -> Int;
    fn DeleteFileW(lpFileName: ConstWCharPtr) -> Int;
    fn DeleteService(hService: ScHandle) -> Int;
    fn EnterCriticalSection(lpCriticalSection: VoidPtr);
    fn ExitThread(dwExitCode: DWord);
    fn FindClose(hFindFile: Handle) -> Int;
    fn FindFirstFileA(lpFileName: ConstCharPtr, lpFindFileData: VoidPtr) -> Handle;
    fn FindFirstFileW(lpFileName: ConstWCharPtr, lpFindFileData: VoidPtr) -> Handle;
    fn FindNextFileA(hFindFile: Handle, lpFindFileData: VoidPtr) -> Int;
    fn FindNextFileW(hFindFile: Handle, lpFindFileData: VoidPtr) -> Int;
    fn FindWindowA(lpClassName: LpCStr, lpWindowName: LpCStr) -> Hwnd;
    fn FindWindowW(lpClassName: LpCWStr, lpWindowName: LpCWStr) -> Hwnd;
    fn FlushFileBuffers(hFile: Handle) -> Int;
    fn FormatMessageA(dwFlags: DWord, lpSource: VoidPtr, dwMessageId: DWord, dwLanguageId: DWord, lpBuffer: CharPtr, nSize: DWord, Arguments: VoidPtr) -> DWord;
    fn FormatMessageW(dwFlags: DWord, lpSource: VoidPtr, dwMessageId: DWord, dwLanguageId: DWord, lpBuffer: WCharPtr, nSize: DWord, Arguments: VoidPtr) -> DWord;
    fn FreeLibrary(hLibModule: Handle) -> Int;
    fn GetCommandLineA() -> CharPtr;
    fn GetCommandLineW() -> WCharPtr;
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> DWord;
    fn GetCurrentThread() -> Handle;
    fn GetCurrentThreadId() -> DWord;
    fn GetEnvironmentVariableA(lpName: ConstCharPtr, lpBuffer: CharPtr, nSize: DWord) -> DWord;
    fn GetEnvironmentVariableW(lpName: ConstWCharPtr, lpBuffer: WCharPtr, nSize: DWord) -> DWord;
    fn GetExitCodeThread(hThread: Handle, lpExitCode: VoidPtr) -> Int;
    fn GetFileSize(hFile: Handle, lpFileSizeHigh: VoidPtr) -> DWord;
    fn GetModuleFileNameA(hModule: Handle, lpFilename: CharPtr, nSize: DWord) -> DWord;
    fn GetModuleFileNameW(hModule: Handle, lpFilename: WCharPtr, nSize: DWord) -> DWord;
    fn GetSystemInfo(lpSystemInfo: VoidPtr);
    fn GetTempFileNameA(lpPathName: ConstCharPtr, lpPrefixString: ConstCharPtr, uUnique: UInt, lpTempFileName: CharPtr) -> UInt;
    fn GetTempPathA(nBufferLength: DWord, lpBuffer: CharPtr) -> DWord;
    fn GetTickCount() -> DWord;
    fn GetTickCount64() -> ULong;
    fn GetWindowTextA(hWnd: Hwnd, lpString: CharPtr, nMaxCount: Int) -> Int;
    fn GetWindowTextW(hWnd: Hwnd, lpString: WCharPtr, nMaxCount: Int) -> Int;
    fn GlobalAlloc(uFlags: UInt, dwBytes: SizeT) -> VoidPtr;
    fn GlobalFree(hMem: VoidPtr) -> VoidPtr;
    fn InitializeCriticalSection(lpCriticalSection: VoidPtr);
    fn InternetCloseHandle(hInternet: VoidPtr) -> Int;
    fn InternetOpenA(lpszAgent: ConstCharPtr, dwAccessType: DWord, lpszProxy: ConstCharPtr, lpszProxyBypass: ConstCharPtr, dwFlags: DWord) -> VoidPtr;
    fn InternetOpenUrlA(hInternet: VoidPtr, lpszUrl: ConstCharPtr, lpszHeaders: ConstCharPtr, dwHeadersLength: DWord, dwFlags: DWord, dwContext: ULong) -> VoidPtr;
    fn InternetReadFile(hFile: VoidPtr, lpBuffer: VoidPtr, dwNumberOfBytesToRead: DWord, lpdwNumberOfBytesRead: VoidPtr) -> Int;
    fn IsDebuggerPresent() -> Int;
    fn LeaveCriticalSection(lpCriticalSection: VoidPtr);
    fn LocalAlloc(uFlags: UInt, uBytes: SizeT) -> VoidPtr;
    fn LocalFree(hMem: VoidPtr) -> VoidPtr;
    fn MessageBoxA(hWnd: Hwnd, lpText: ConstCharPtr, lpCaption: ConstCharPtr, uType: UInt) -> Int;
    fn MessageBoxW(hWnd: Hwnd, lpText: ConstWCharPtr, lpCaption: ConstWCharPtr, uType: UInt) -> Int;
    fn MoveFileA(lpExistingFileName: ConstCharPtr, lpNewFileName: ConstCharPtr) -> Int;
    fn MultiByteToWideChar(CodePage: UInt, dwFlags: DWord, lpMultiByteStr: ConstCharPtr, cbMultiByte: Int, lpWideCharStr: WCharPtr, cchWideChar: Int) -> Int;
    fn NtQueryInformationProcess(ProcessHandle: Handle, ProcessInformationClass: Int, ProcessInformation: VoidPtr, ProcessInformationLength: UInt, ReturnLength: VoidPtr) -> Ntstatus;
    fn NtQuerySystemInformation(SystemInformationClass: Int, SystemInformation: VoidPtr, SystemInformationLength: UInt, ReturnLength: VoidPtr) -> Ntstatus;
    fn OpenProcess(dwDesiredAccess: DWord, bInheritHandle: Int, dwProcessId: DWord) -> Handle;
    fn OpenSCManagerA(lpMachineName: LpCStr, lpDatabaseName: LpCStr, dwDesiredAccess: DWord) -> ScHandle;
    fn OpenSCManagerW(lpMachineName: LpCWStr, lpDatabaseName: LpCWStr, dwDesiredAccess: DWord) -> ScHandle;
    fn OpenServiceA(hSCManager: ScHandle, lpServiceName: LpCStr, dwDesiredAccess: DWord) -> ScHandle;
    fn OpenServiceW(hSCManager: ScHandle, lpServiceName: LpCWStr, dwDesiredAccess: DWord) -> ScHandle;
    fn OutputDebugStringA(lpOutputString: ConstCharPtr);
    fn OutputDebugStringW(lpOutputString: ConstWCharPtr);
    fn PostMessageA(hWnd: Hwnd, Msg: UInt, wParam: WParam, lParam: LParam) -> Int;
    fn PostMessageW(hWnd: Hwnd, Msg: UInt, wParam: WParam, lParam: LParam) -> Int;
    fn QueryPerformanceCounter(lpPerformanceCount: VoidPtr) -> Int;
    fn QueryPerformanceFrequency(lpFrequency: VoidPtr) -> Int;
    fn RaiseException(dwExceptionCode: DWord, dwExceptionFlags: DWord, nNumberOfArguments: DWord, lpArguments: VoidPtr);
    fn ReadProcessMemory(hProcess: Handle, lpBaseAddress: VoidPtr, lpBuffer: VoidPtr, nSize: SizeT, lpNumberOfBytesRead: VoidPtr) -> Int;
    fn RegCloseKey(hKey: HKey) -> LStatus;
    fn RegCreateKeyExA(hKey: HKey, lpSubKey: LpCStr, Reserved: DWord, lpClass: CharPtr, dwOptions: DWord, samDesired: RegSam, lpSecurityAttributes: VoidPtr, phkResult: PhKey, lpdwDisposition: LpDWord) -> LStatus;
    fn RegOpenKeyExW(hKey: HKey, lpSubKey: LpCWStr, ulOptions: DWord, samDesired: RegSam, phkResult: PhKey) -> LStatus;
    fn RegQueryValueExA(hKey: HKey, lpValueName: LpCStr, lpReserved: LpDWord, lpType: LpDWord, lpData: LpByte, lpcbData: LpDWord) -> LStatus;
    fn RegQueryValueExW(hKey: HKey, lpValueName: LpCWStr, lpReserved: LpDWord, lpType: LpDWord, lpData: LpByte, lpcbData: LpDWord) -> LStatus;
    fn RegSetValueExW(hKey: HKey, lpValueName: LpCWStr, Reserved: DWord, dwType: DWord, lpData: ConstVoidPtr, cbData: DWord) -> LStatus;
    fn ReleaseMutex(hMutex: Handle) -> Int;
    fn ResetEvent(hEvent: Handle) -> Int;
    fn SendMessageA(hWnd: Hwnd, Msg: UInt, wParam: WParam, lParam: LParam) -> LResult;
    fn SendMessageW(hWnd: Hwnd, Msg: UInt, wParam: WParam, lParam: LParam) -> LResult;
    fn SetEvent(hEvent: Handle) -> Int;
    fn SetFilePointer(hFile: Handle, lDistanceToMove: Long, lpDistanceToMoveHigh: VoidPtr, dwMoveMethod: DWord) -> DWord;
    fn SetUnhandledExceptionFilter(lpTopLevelExceptionFilter: VoidPtr) -> VoidPtr;
    fn ShellExecuteA(hwnd: Handle, lpOperation: ConstCharPtr, lpFile: ConstCharPtr, lpParameters: ConstCharPtr, lpDirectory: ConstCharPtr, nShowCmd: Int) -> VoidPtr;
    fn ShellExecuteW(hwnd: Handle, lpOperation: ConstWCharPtr, lpFile: ConstWCharPtr, lpParameters: ConstWCharPtr, lpDirectory: ConstWCharPtr, nShowCmd: Int) -> VoidPtr;
    fn SleepEx(dwMilliseconds: DWord, bAlertable: Int) -> DWord;
    fn StartServiceA(hService: ScHandle, dwNumServiceArgs: DWord, lpServiceArgVectors: VoidPtr) -> Int;
    fn TerminateProcess(hProcess: Handle, uExitCode: UInt) -> Int;
    fn URLDownloadToFileA(pCaller: VoidPtr, szURL: LpCStr, szFileName: LpCStr, Reserved: DWord, lpfnCB: VoidPtr) -> HResult;
    fn URLDownloadToFileW(pCaller: VoidPtr, szURL: ConstWCharPtr, szFileName: ConstWCharPtr, Reserved: DWord, lpfnCB: VoidPtr) -> Ntstatus;
    fn VirtualQuery(lpAddress: VoidPtr, lpBuffer: VoidPtr, dwLength: SizeT) -> SizeT;
    fn WSACleanup() -> Int;
    fn WSAGetLastError() -> Int;
    fn WSAStartup(wVersionRequested: UInt, lpWSAData: VoidPtr) -> Int;
    fn WaitForMultipleObjects(nCount: DWord, lpHandles: VoidPtr, bWaitAll: Int, dwMilliseconds: DWord) -> DWord;
    fn WaitForSingleObject(hHandle: Handle, dwMilliseconds: DWord) -> DWord;
    fn WideCharToMultiByte(CodePage: UInt, dwFlags: DWord, lpWideCharStr: ConstWCharPtr, cchWideChar: Int, lpMultiByteStr: CharPtr, cbMultiByte: Int, lpDefaultChar: ConstCharPtr, lpUsedDefaultChar: VoidPtr) -> Int;
};
