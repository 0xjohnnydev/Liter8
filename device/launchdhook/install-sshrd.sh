#!/bin/sh
# Update only the hook and its session controller on an already mounted SSHRD.
set -eu
cd "$(dirname "$0")"
SSH=../../tools/sshdev
sh build.sh
"$SSH" 'test -f /mnt1/sbin/launchd && test -d /mnt1/usr/lib && test -d /mnt2/jb/usr/bin' || {
    echo 'Mount System at /mnt1 and Data at /mnt2 in SSHRD first.' >&2
    exit 1
}
CHECK_DIR=$(mktemp -d)
trap 'rm -rf "$CHECK_DIR"' EXIT HUP INT TERM

# What the installed launchd actually loads, read from the device rather than
# assumed. This script only ever writes /usr/lib/lhook. On a device provisioned
# before the hook moved, launchd still names /usr/lib/lhook.dylib, so that write
# installs a hook nothing loads while the old one keeps running with the
# pre-session-guard behaviour that treats a leftover empty marker as enabled.
# Reporting success there is the one outcome this script must not produce.
#
# Read on the host: otool is here, and the ramdisk is not known to have it.
"$SSH" 'cat /mnt1/sbin/launchd' > "$CHECK_DIR/launchd.ondevice"
HOOK_PATH=$(otool -l "$CHECK_DIR/launchd.ondevice" \
    | grep -A3 LC_LOAD_WEAK_DYLIB \
    | sed -n 's/^ *name \(\/usr\/lib\/lhook[^ ]*\) .*/\1/p' | head -1)
case "$HOOK_PATH" in
    /usr/lib/lhook) ;;
    /usr/lib/lhook.dylib)
        echo "This device's launchd loads /usr/lib/lhook.dylib, the path used before the" >&2
        echo 'hook moved. Writing /usr/lib/lhook here would leave that older hook active' >&2
        echo 'and the session guard not in effect, so this stops instead.' >&2
        echo 'Run the full provisioner: it recognises that launchd and replaces it.' >&2
        exit 1 ;;
    '')
        echo 'This launchd has no lhook load command, so nothing would load what this' >&2
        echo 'script writes. Provision the device first.' >&2
        exit 1 ;;
    *)
        echo "This launchd loads an unrecognised hook path: $HOOK_PATH" >&2
        exit 1 ;;
esac

# The load command says this device was hooked by this workflow at some point,
# not that it was hooked from this tree. What this script writes is not
# build-specific (lhook.dylib and lhookctl carry no profile input), so writing
# them onto another build's launchd is not itself dangerous. It does reliably
# mean the wrong tree is open for this device, though, and this is the one
# script that writes into PID 1's load path without the profile and hash gates
# the full provisioner applies. So it compares what it can and stops.
#
# Only when the comparison is possible: a tree that has not built its launchd
# payload yet has nothing to compare, and that is not a reason to refuse a hook
# update.
if [ -f ../payload/launchd.hooked ] \
    && ! cmp -s ../payload/launchd.hooked "$CHECK_DIR/launchd.ondevice"; then
    echo "This device's /sbin/launchd is not the image this tree built." >&2
    echo 'The hook and controller are not build-specific, so this would still' >&2
    echo 'load, but it almost always means the wrong tree is open for this' >&2
    echo 'device. Run the full provisioner, which checks the firmware profile.' >&2
    exit 1
fi

"$SSH" '
if [ -f /mnt1/usr/lib/lhook ] && [ ! -e /mnt1/usr/lib/lhook.before-session-guard ]; then
    cp /mnt1/usr/lib/lhook /mnt1/usr/lib/lhook.before-session-guard || exit 1
fi
if [ -f /mnt2/jb/usr/bin/lhookctl ] && [ ! -e /mnt2/jb/usr/bin/lhookctl.before-session-guard ]; then
    cp /mnt2/jb/usr/bin/lhookctl /mnt2/jb/usr/bin/lhookctl.before-session-guard || exit 1
fi'
"$SSH" 'cat > /mnt1/usr/lib/lhook.session-new' < lhook.dylib
"$SSH" 'cat > /mnt2/jb/usr/bin/lhookctl.session-new' < lhookctl
"$SSH" 'cat /mnt1/usr/lib/lhook.session-new' > "$CHECK_DIR/lhook"
"$SSH" 'cat /mnt2/jb/usr/bin/lhookctl.session-new' > "$CHECK_DIR/lhookctl"
cmp lhook.dylib "$CHECK_DIR/lhook"
cmp lhookctl "$CHECK_DIR/lhookctl"
"$SSH" '
chmod 0755 /mnt1/usr/lib/lhook.session-new /mnt2/jb/usr/bin/lhookctl.session-new &&
mv -f /mnt2/jb/usr/bin/lhookctl.session-new /mnt2/jb/usr/bin/lhookctl &&
mv -f /mnt1/usr/lib/lhook.session-new /mnt1/usr/lib/lhook &&
sync'
# An existing deny file overrides lhook's built-in defaults, so a default added
# to this tree would never apply on a device that already has one. Only defaults
# added after the file first shipped are merged: removing an older default is
# how an operator allows injection, and that choice must survive an update.
# ponytail: a fixed list; add each future default here alongside lhook.deny.
# The leading newline covers a file without a trailing one; blank lines are
# ignored by the parser.
"$SSH" '
f=/mnt2/jb/etc/lhook.deny
[ -f "$f" ] || exit 0
for name in GSSCred; do
    grep -qx "$name" "$f" || { printf "\n%s\n" "$name" >> "$f" && echo "deny list: added $name"; }
done'
echo 'Hook installed with readback verification. Boot normally, then run lhookctl enable after the interface is up.'
