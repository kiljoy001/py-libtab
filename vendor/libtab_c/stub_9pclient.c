/*
 * Stub for the 9P-client mount entry point libauth's nsamount.c calls.
 *
 * py-libtab links against libauth (a real libtab dependency chain via
 * tab_persist.c's auth-adjacent paths) but not lib9pclient, since the
 * only libtab caller of the 9P client stack is tab_open_dial() — the
 * optional remote-write path for dialing a live 9P fileserver, which is
 * out of scope for a local .tab file library and would otherwise pull
 * in lib9pclient's libthread dependency (Plan 9's own cooperative
 * scheduler) just to satisfy a link-time reference nothing calls.
 *
 * If a caller does invoke tab_open_dial(), this stub fails loudly
 * instead of silently mounting nothing.
 */
#include <u.h>
#include <libc.h>
#include <9pclient.h>

CFsys*
nsmount(char *name, char *aname)
{
	USED(name);
	USED(aname);
	werrstr("nsmount: 9P client support not linked into this build "
		"(tab_open_dial is unavailable)");
	return nil;
}

CFid*
fscreate(CFsys *fs, char *name, int mode, ulong perm)
{
	USED(fs); USED(name); USED(mode); USED(perm);
	werrstr("fscreate: 9P client support not linked into this build");
	return nil;
}

long
fswrite(CFid *fid, void *buf, long n)
{
	USED(fid); USED(buf); USED(n);
	werrstr("fswrite: 9P client support not linked into this build");
	return -1;
}

void
fsclose(CFid *fid)
{
	USED(fid);
}

void
fsunmount(CFsys *fs)
{
	USED(fs);
}
