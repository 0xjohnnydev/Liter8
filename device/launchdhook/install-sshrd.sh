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
"$SSH" '
if [ -f /mnt1/usr/lib/lhook ] && [ ! -e /mnt1/usr/lib/lhook.before-session-guard ]; then
    cp /mnt1/usr/lib/lhook /mnt1/usr/lib/lhook.before-session-guard || exit 1
fi
if [ -f /mnt2/jb/usr/bin/lhookctl ] && [ ! -e /mnt2/jb/usr/bin/lhookctl.before-session-guard ]; then
    cp /mnt2/jb/usr/bin/lhookctl /mnt2/jb/usr/bin/lhookctl.before-session-guard || exit 1
fi'
"$SSH" 'cat > /mnt1/usr/lib/lhook.session-new' < lhook.dylib
"$SSH" 'cat > /mnt2/jb/usr/bin/lhookctl.session-new' < lhookctl
CHECK_DIR=$(mktemp -d)
trap 'rm -rf "$CHECK_DIR"' EXIT HUP INT TERM
"$SSH" 'cat /mnt1/usr/lib/lhook.session-new' > "$CHECK_DIR/lhook"
"$SSH" 'cat /mnt2/jb/usr/bin/lhookctl.session-new' > "$CHECK_DIR/lhookctl"
cmp lhook.dylib "$CHECK_DIR/lhook"
cmp lhookctl "$CHECK_DIR/lhookctl"
"$SSH" '
chmod 0755 /mnt1/usr/lib/lhook.session-new /mnt2/jb/usr/bin/lhookctl.session-new &&
mv -f /mnt2/jb/usr/bin/lhookctl.session-new /mnt2/jb/usr/bin/lhookctl &&
mv -f /mnt1/usr/lib/lhook.session-new /mnt1/usr/lib/lhook &&
sync'
echo 'Hook installed with readback verification. Boot normally, then run lhookctl enable after the interface is up.'
