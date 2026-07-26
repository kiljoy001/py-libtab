/*
 * getrandom() compatibility shim.
 *
 * tab_hashed.c calls getrandom(2) for the argon2id salt. The glibc
 * *wrapper* for getrandom was only added in glibc 2.25 — manylinux2014
 * ships glibc 2.17, where linking against getrandom fails even though
 * the kernel syscall (Linux >= 3.17) is available. This provides a weak
 * getrandom that goes straight to the syscall, so the build links on old
 * glibc while still deferring to the real glibc getrandom where present.
 *
 * Compiled with normal system headers (NOT plan9port's u.h/libc.h) to
 * avoid the plan9port name remapping; declared `weak` so it never
 * conflicts with a real glibc getrandom at link time.
 */
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#ifndef SYS_getrandom
#  if defined(__x86_64__)
#    define SYS_getrandom 318
#  endif
#endif

__attribute__((weak))
long
getrandom(void *buf, unsigned long buflen, unsigned int flags)
{
#ifdef SYS_getrandom
	return syscall(SYS_getrandom, buf, buflen, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}
