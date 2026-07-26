#!/bin/bash
# Rebuild the plan9port libraries libtab needs (lib9, libbio, libndb,
# libsec, libauth) as position-independent code, from the vendored
# source copy in this directory. File lists are transcribed by hand
# from each library's real mkfile (read as data, not executed) so we
# get exactly the files plan9port's own build includes/excludes —
# not a blind glob of every *.c file in the tree.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P9="$HERE/plan9port"
SRC="$P9/src"
INC="$P9/include"

# SANITIZE=1 builds an AddressSanitizer + UndefinedBehaviorSanitizer
# variant into libtab-asan.so, with its own object dirs (pic-libs-asan)
# so it never collides with the normal -O2 build. The sanitizer build is
# what the fuzz harness (tests/fuzz/) loads: it turns a one-byte
# over-read in the C parser — reachable from an untrusted .tab file —
# into a loud, located crash instead of silent corruption. Load it with
#   LD_PRELOAD=$(gcc -print-file-name=libasan.so) ASAN_OPTIONS=...
# so the sanitizer runtime initializes before the .so is dlopen'd.
SAN_FLAGS=()
OUT="$HERE/pic-libs"
SO_NAME="libtab.so"
if [ "${SANITIZE:-0}" = "1" ]; then
    SAN_FLAGS=(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    OUT="$HERE/pic-libs-asan"
    SO_NAME="libtab-asan.so"
    echo "=== SANITIZER BUILD (address,undefined) -> $SO_NAME ==="
fi

mkdir -p "$OUT"
CC=(gcc -DPLAN9PORT -I"$INC" -O2 -fPIC -w "${SAN_FLAGS[@]+"${SAN_FLAGS[@]}"}" -c)

build_lib() {
    local libname="$1"; shift
    local srcdir="$1"; shift
    local objdir
    objdir="$OUT/obj-$libname"
    mkdir -p "$objdir"
    echo "=== $libname ($# files) ==="
    for f in "$@"; do
        extra=()
        if [ "$(basename "$f")" = "get9root.c" ]; then
            # mkfile: get9root.$O: get9root.c ; $CC $CFLAGS -DPLAN9_TARGET=\"$PLAN9_TARGET\" get9root.c
            extra=(-DPLAN9_TARGET="\"$(uname -m)-linux\"")
        fi
        "${CC[@]}" "${extra[@]+"${extra[@]}"}" -I"$srcdir" -o "$objdir/$(basename "$f" .c).o" "$srcdir/$f"
    done
    ar rcs "$OUT/$libname" "$objdir"/*.o
    echo "-> $OUT/$libname"
}

# ---- lib9 ----
LIB9_FMT=(fmt/dofmt.c fmt/fltfmt.c fmt/fmt.c fmt/fmtfd.c fmt/fmtfdflush.c
    fmt/fmtlocale.c fmt/fmtlock.c fmt/fmtnull.c fmt/fmtprint.c
    fmt/fmtquote.c fmt/fmtrune.c fmt/fmtstr.c fmt/fmtvprint.c fmt/fprint.c
    fmt/nan64.c fmt/print.c fmt/runefmtstr.c fmt/runeseprint.c
    fmt/runesmprint.c fmt/runesnprint.c fmt/runesprint.c
    fmt/runevseprint.c fmt/runevsmprint.c fmt/runevsnprint.c fmt/seprint.c
    fmt/smprint.c fmt/snprint.c fmt/sprint.c fmt/strtod.c fmt/vfprint.c
    fmt/vseprint.c fmt/vsmprint.c fmt/vsnprint.c fmt/charstod.c fmt/pow10.c)
# fmt/frexp.c is absent from this checkout's fmt/ dir (mkfile lists it,
# but fltfmt.c's frexp() call resolves fine to glibc's own <math.h>
# frexp when the local one isn't compiled in).
LIB9_UTF=(utf/rune.c utf/runestrcat.c utf/runestrchr.c utf/runestrcmp.c
    utf/runestrcpy.c utf/runestrdup.c utf/runestrlen.c utf/runestrecpy.c
    utf/runestrncat.c utf/runestrncmp.c utf/runestrncpy.c
    utf/runestrrchr.c utf/runestrstr.c utf/runetype.c utf/utfecpy.c
    utf/utflen.c utf/utfnlen.c utf/utfrrune.c utf/utfrune.c utf/utfutf.c)
LIB9_CORE=(_exits.c _p9dialparse.c _p9dir.c announce.c argv0.c atexit.c
    atoi.c atol.c atoll.c atnotify.c await.c cistrcmp.c cistrncmp.c
    cistrstr.c cleanname.c convD2M.c convM2D.c convM2S.c convS2M.c
    crypt.c ctime.c dial.c dirfstat.c dirfwstat.c dirmodefmt.c dirstat.c
    dirwstat.c dup.c encodefmt.c errstr.c exec.c execl.c exitcode.c
    fcallfmt.c frand.c get9root.c getcallerpc.c getenv.c getfields.c
    getnetconn.c getns.c getuser.c getwd.c jmp.c lrand.c lnrand.c main.c
    malloc.c malloctag.c mallocz.c nan.c needsrcquote.c needstack.c
    netcrypt.c netmkaddr.c notify.c nrand.c nulldir.c open.c opentemp.c
    pin.c pipe.c post9p.c postnote.c qlock.c quote.c rand.c read9pmsg.c
    readcons.c readn.c rfork.c searchpath.c sendfd.c sleep.c strdup.c
    strecpy.c sysfatal.c syslog.c sysname.c time.c tm2sec.c tokenize.c
    truerand.c u16.c u32.c u64.c unsharp.c wait.c waitpid.c write.c
    zoneinfo.c)
build_lib lib9.a "$SRC/lib9" "${LIB9_FMT[@]}" "${LIB9_UTF[@]}" "${LIB9_CORE[@]}"

# ---- libbio ----
LIBBIO=(bbuffered.c bfildes.c bflush.c bgetc.c bgetrune.c bgetd.c binit.c
    boffset.c bprint.c bputc.c bputrune.c brdline.c brdstr.c bread.c
    bseek.c bvprint.c bwrite.c)
build_lib libbio.a "$SRC/libbio" "${LIBBIO[@]}"

# ---- libndb (csgetval/csipinfo/dnsquery excluded, per mkfile's #comments) ----
LIBNDB=(ipattr.c ndbaux.c ndbcache.c ndbcat.c ndbconcatenate.c
    ndbdiscard.c ndbfree.c ndbgetipaddr.c ndbgetval.c ndbhash.c
    ndbipinfo.c ndblookval.c ndbopen.c ndbparse.c ndbreorder.c
    ndbsubstitute.c sysdnsquery.c)
build_lib libndb.a "$SRC/libndb" "${LIBNDB[@]}"

# ---- libauth (amount/auth_chuid/auth_wep/login/newns/noworld excluded) ----
LIBAUTH=(amount_getkey.c attr.c auth_attr.c auth_challenge.c
    auth_getkey.c auth_getuserpasswd.c auth_proxy.c auth_respond.c
    auth_rpc.c auth_userpasswd.c fsamount.c nsamount.c)
build_lib libauth.a "$SRC/libauth" "${LIBAUTH[@]}"

# ---- libsec ----
LIBSEC=(aes.c blowfish.c ccpoly.c chacha.c chachablock.c decodepem.c
    des.c des3CBC.c des3ECB.c desCBC.c desECB.c desmodes.c dsaalloc.c
    dsagen.c dsaprimes.c dsaprivtopub.c dsasign.c dsaverify.c egalloc.c
    egdecrypt.c egencrypt.c eggen.c egprivtopub.c egsign.c egverify.c
    fastrand.c genprime.c genrandom.c gensafeprime.c genstrongprime.c
    hmac.c hkdf.c md4.c md5.c md5block.c md5pickle.c nfastrand.c
    pbkdf2.c poly1305.c prng.c probably_prime.c rc4.c readcert.c
    rsaalloc.c rsadecrypt.c rsaencrypt.c rsafill.c rsagen.c
    rsaprivtopub.c sha1.c sha1block.c sha1pickle.c sha2_64.c sha2_128.c
    sha2block64.c sha2block128.c smallprimetest.c thumb.c tlshand.c
    tsmemcmp.c x509.c)
build_lib libsec.a "$SRC/libsec/port" "${LIBSEC[@]}"

# ---- libtab itself + monocypher + the 9pclient stub ----
LIBTAB_SRC="$HERE/libtab_c"
LIBTAB_OFILES=(tab_codec.c tab_create.c tab_error.c tab_hashed.c tab_iter.c
    tab_open.c tab_persist.c tab_row.c tab_rowmap.c tab_serialize.c
    tab_signed.c monocypher.c stub_9pclient.c)
objdir="$OUT/obj-libtab"
mkdir -p "$objdir"
echo "=== libtab (${#LIBTAB_OFILES[@]} files) ==="
for f in "${LIBTAB_OFILES[@]}"; do
    "${CC[@]}" -I"$LIBTAB_SRC" -o "$objdir/$(basename "$f" .c).o" "$LIBTAB_SRC/$f"
done

echo "=== linking $SO_NAME ==="
# --no-undefined is dropped under ASan: the sanitizer runtime resolves
# its interceptor symbols at load time (via LD_PRELOAD), so they are
# legitimately undefined in the .so itself.
LINK_EXTRA=(-Wl,--no-undefined)
if [ "${SANITIZE:-0}" = "1" ]; then
    LINK_EXTRA=()
fi
gcc -shared -fPIC "${SAN_FLAGS[@]+"${SAN_FLAGS[@]}"}" -o "$HERE/$SO_NAME" \
    "$objdir"/*.o \
    -L "$OUT" -lndb -lbio -lauth -lsec -l9 -lpthread \
    "${LINK_EXTRA[@]+"${LINK_EXTRA[@]}"}"

echo "=== done ==="
ls -la "$OUT"/*.a "$HERE/$SO_NAME"
