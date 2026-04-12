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
    fn GetProcAddress(hModule: Handle, lpProcName: ConstCharPtr) -> VoidPtr;
    fn LoadLibraryA(lpLibFileName: ConstCharPtr) -> Handle;
    fn LoadLibraryW(lpLibFileName: ConstWCharPtr) -> Handle;
    fn GetModuleHandleA(lpModuleName: ConstCharPtr) -> Handle;
    fn GetModuleHandleW(lpModuleName: ConstWCharPtr) -> Handle;

    // Process
    fn CreateProcessA(lpApplicationName: ConstCharPtr, lpCommandLine: CharPtr, lpProcessAttributes: VoidPtr, lpThreadAttributes: VoidPtr, bInheritHandles: Bool, dwCreationFlags: DWord, lpEnvironment: VoidPtr, lpCurrentDirectory: ConstCharPtr, lpStartupInfo: VoidPtr, lpProcessInformation: VoidPtr) -> Bool;
    fn CreateProcessW(lpApplicationName: ConstWCharPtr, lpCommandLine: WCharPtr, lpProcessAttributes: VoidPtr, lpThreadAttributes: VoidPtr, bInheritHandles: Bool, dwCreationFlags: DWord, lpEnvironment: VoidPtr, lpCurrentDirectory: ConstWCharPtr, lpStartupInfo: VoidPtr, lpProcessInformation: VoidPtr) -> Bool;
    fn CreateRemoteThread(hProcess: Handle, lpThreadAttributes: VoidPtr, dwStackSize: SizeT, lpStartAddress: VoidPtr, lpParameter: LpVoid, dwCreationFlags: DWord, lpThreadId: VoidPtr) -> Handle;
    fn WriteProcessMemory(hProcess: Handle, lpBaseAddress: LpVoid, lpBuffer: ConstVoidPtr, nSize: SizeT, lpNumberOfBytesWritten: VoidPtr) -> Bool;

    // Error
    fn GetLastError() -> DWord;
    fn SetLastError(dwErrCode: DWord);

    // Registry
    fn RegOpenKeyExA(hKey: Handle, lpSubKey: ConstCharPtr, ulOptions: DWord, samDesired: DWord, phkResult: VoidPtr) -> Long;
    fn RegSetValueExA(hKey: Handle, lpValueName: ConstCharPtr, Reserved: DWord, dwType: DWord, lpData: ConstVoidPtr, cbData: DWord) -> Long;
};
