//! POSIX / C standard library function signatures.

use crate::signatures::*;

pub static LIBC_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // stdio
    fn printf(format: ConstCharPtr, ...) -> Int;
    fn fprintf(stream: FilePtr, format: ConstCharPtr, ...) -> Int;
    fn sprintf(buf: CharPtr, format: ConstCharPtr, ...) -> Int;
    fn snprintf(buf: CharPtr, size: SizeT, format: ConstCharPtr, ...) -> Int;
    fn puts(s: ConstCharPtr) -> Int;
    fn fputs(s: ConstCharPtr, stream: FilePtr) -> Int;
    fn fgets(s: CharPtr, size: Int, stream: FilePtr) -> CharPtr;
    fn fread(ptr: VoidPtr, size: SizeT, nmemb: SizeT, stream: FilePtr) -> SizeT;
    fn fwrite(ptr: ConstVoidPtr, size: SizeT, nmemb: SizeT, stream: FilePtr) -> SizeT;
    fn fopen(path: ConstCharPtr, mode: ConstCharPtr) -> FilePtr;
    fn fclose(stream: FilePtr) -> Int;
    fn fseek(stream: FilePtr, offset: Long, whence: Int) -> Int;
    fn ftell(stream: FilePtr) -> Long;
    fn feof(stream: FilePtr) -> Int;
    fn ferror(stream: FilePtr) -> Int;
    fn fflush(stream: FilePtr) -> Int;
    fn fputc(c: Int, stream: FilePtr) -> Int;
    fn fgetc(stream: FilePtr) -> Int;
    fn putchar(c: Int) -> Int;
    fn getchar() -> Int;
    fn fprintf_stderr(format: ConstCharPtr, ...) -> Int;
    fn wprintf(format: ConstWCharPtr, ...) -> Int;
    fn fwprintf(stream: FilePtr, format: ConstWCharPtr, ...) -> Int;
    fn fwprintf_stderr(format: ConstWCharPtr, ...) -> Int;
    fn scanf(format: ConstCharPtr, ...) -> Int;
    fn fscanf(stream: FilePtr, format: ConstCharPtr, ...) -> Int;

    // stdlib
    fn malloc(size: SizeT) -> VoidPtr;
    fn calloc(nmemb: SizeT, size: SizeT) -> VoidPtr;
    fn realloc(ptr: VoidPtr, size: SizeT) -> VoidPtr;
    fn free(ptr: VoidPtr);
    fn atoi(s: ConstCharPtr) -> Int;
    fn atol(s: ConstCharPtr) -> Long;
    fn strtol(s: ConstCharPtr, endptr: CharPtr, base: Int) -> Long;
    fn strtoul(s: ConstCharPtr, endptr: CharPtr, base: Int) -> ULong;
    fn exit(status: Int);
    fn abort();
    fn abs(x: Int) -> Int;
    fn qsort(base: VoidPtr, nmemb: SizeT, size: SizeT, compar: VoidPtr);

    // string
    fn strlen(s: ConstCharPtr) -> SizeT;
    fn strcpy(dest: CharPtr, src: ConstCharPtr) -> CharPtr;
    fn strncpy(dest: CharPtr, src: ConstCharPtr, n: SizeT) -> CharPtr;
    fn strcmp(s1: ConstCharPtr, s2: ConstCharPtr) -> Int;
    fn strncmp(s1: ConstCharPtr, s2: ConstCharPtr, n: SizeT) -> Int;
    fn strcat(dest: CharPtr, src: ConstCharPtr) -> CharPtr;
    fn strncat(dest: CharPtr, src: ConstCharPtr, n: SizeT) -> CharPtr;
    fn strchr(s: ConstCharPtr, c: Int) -> CharPtr;
    fn strrchr(s: ConstCharPtr, c: Int) -> CharPtr;
    fn strstr(haystack: ConstCharPtr, needle: ConstCharPtr) -> CharPtr;
    fn memcpy(dest: VoidPtr, src: ConstVoidPtr, n: SizeT) -> VoidPtr;
    fn memset(s: VoidPtr, c: Int, n: SizeT) -> VoidPtr;
    fn memmove(dest: VoidPtr, src: ConstVoidPtr, n: SizeT) -> VoidPtr;
    fn memcmp(s1: ConstVoidPtr, s2: ConstVoidPtr, n: SizeT) -> Int;
    fn strerror(errnum: Int) -> CharPtr;

    // unistd / posix
    fn read(fd: Fd, buf: VoidPtr, count: SizeT) -> Long;
    fn write(fd: Fd, buf: ConstVoidPtr, count: SizeT) -> Long;
    fn open(path: ConstCharPtr, flags: Int, ...) -> Fd;
    fn close(fd: Fd) -> Int;
    fn fork() -> Int;
    fn execve(path: ConstCharPtr, argv: VoidPtr, envp: VoidPtr) -> Int;
    fn getpid() -> Int;
    fn sleep(seconds: UInt) -> UInt;
    fn dup2(oldfd: Fd, newfd: Fd) -> Int;
    fn pipe(pipefd: VoidPtr) -> Int;

    // socket
    fn socket(domain: Int, ty: Int, protocol: Int) -> SockFd;
    fn bind(sockfd: SockFd, addr: ConstVoidPtr, addrlen: UInt) -> Int;
    fn listen(sockfd: SockFd, backlog: Int) -> Int;
    fn accept(sockfd: SockFd, addr: VoidPtr, addrlen: VoidPtr) -> SockFd;
    fn connect(sockfd: SockFd, addr: ConstVoidPtr, addrlen: UInt) -> Int;
    fn send(sockfd: SockFd, buf: ConstVoidPtr, len: SizeT, flags: Int) -> Long;
    fn recv(sockfd: SockFd, buf: VoidPtr, len: SizeT, flags: Int) -> Long;
    fn sendto(sockfd: SockFd, buf: ConstVoidPtr, len: SizeT, flags: Int, dest_addr: ConstVoidPtr, addrlen: UInt) -> Long;
    fn recvfrom(sockfd: SockFd, buf: VoidPtr, len: SizeT, flags: Int, src_addr: VoidPtr, addrlen: VoidPtr) -> Long;
    fn setsockopt(sockfd: SockFd, level: Int, optname: Int, optval: ConstVoidPtr, optlen: UInt) -> Int;
    fn getsockopt(sockfd: SockFd, level: Int, optname: Int, optval: VoidPtr, optlen: VoidPtr) -> Int;
    fn shutdown(sockfd: SockFd, how: Int) -> Int;
};
