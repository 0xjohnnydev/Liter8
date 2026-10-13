#!/var/jb/bin/sh
#
# Re-sign TweakInject dylibs ad-hoc. Installed by finalize.sh to
# /var/jb/usr/libexec/liter8/tweaksign, run by dpkg after every run that changes
# packages (liter8-tweaksign.cfg) and once by finalize itself.
#
# Theos, and so most repo tweaks, signs with ldid's default flags=0x0. Measured on
# n104 24B5099f: SpringBoard refuses such a dylib and ElleKit's injector discards
# the dlopen error, so the tweak silently never loads, while a plain process loads
# the same file and the same dylib signed ad-hoc (flags=0x2) loads in SpringBoard.
#
# Only a dylib with a slice that is not ad-hoc is touched, so liter8's own tweaks
# and anything already ad-hoc stay byte-identical. A re-signed file no longer
# matches dpkg's recorded md5, so dpkg -V reports it; that is expected.
#
# --list prints the names that need signing and changes nothing. finalize.sh
# --check pipes this file over ssh to use it, so the rule exists in one place.
#
# As the dpkg hook it never exits non-zero: a failing post-invoke hook makes dpkg
# report an error, which would break apt and Sileo installs over a signing
# problem. --list exits 2 when ldid is missing, so finalize can say why.

PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin
DIR=/var/jb/usr/lib/TweakInject
LIST_ONLY=0
[ "${1:-}" = --list ] && LIST_ONLY=1

# ldid ships with the Procursus bootstrap. Without it ldid -h prints nothing and
# every dylib would look unsigned, so stop instead of guessing.
if ! command -v ldid >/dev/null 2>&1; then
    echo "liter8 tweaksign: ldid not found in $PATH; nothing checked or re-signed (apt install ldid)" >&2
    [ "$LIST_ONLY" = 1 ] && exit 2
    exit 0
fi

# True when ldid reports no signature or any slice whose flags lack adhoc.
needs_signing() {
    slices=$(ldid -h "$1" 2>/dev/null | grep 'CodeDirectory')
    [ -z "$slices" ] && return 0
    printf '%s\n' "$slices" | grep -qv 'adhoc'
}

for dylib in "$DIR"/*.dylib; do
    [ -f "$dylib" ] && [ ! -L "$dylib" ] || continue
    needs_signing "$dylib" || continue

    name=${dylib##*/}
    if [ "$LIST_ONLY" = 1 ]; then
        echo "$name"
        continue
    fi
    # Signed as a copy and renamed into place, so a process loading the tweak
    # at this moment sees either the old file or the finished one.
    tmp="$dylib.liter8-sign"
    rm -f "$tmp" "$tmp.xml"
    cp -p "$dylib" "$tmp" || { echo "liter8 tweaksign: could not copy $name" >&2; continue; }

    # Keep any entitlements; ldid -S without a file would drop them.
    ents=$(ldid -e "$dylib" 2>/dev/null)
    if [ -n "$ents" ]; then
        printf '%s\n' "$ents" > "$tmp.xml"
        ldid -S"$tmp.xml" -Cadhoc -I"$name" "$tmp"
        rc=$?
        rm -f "$tmp.xml"
    else
        ldid -S -Cadhoc -I"$name" "$tmp"
        rc=$?
    fi

    if [ "$rc" -ne 0 ] || needs_signing "$tmp"; then
        echo "liter8 tweaksign: could not re-sign $name, left as it was" >&2
        rm -f "$tmp"
        continue
    fi
    mv -f "$tmp" "$dylib" && echo "liter8 tweaksign: re-signed $name ad-hoc"
done
exit 0
