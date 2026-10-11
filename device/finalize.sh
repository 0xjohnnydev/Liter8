#!/bin/zsh
#
# Finish the extracted rootless bootstrap after the first normal boot.
#
# This cannot run from SSHRD. Procursus is mounted at /var/jb only during a
# normal boot, and LaunchServices plus SpringBoard do not exist in the ramdisk.
#
#   ./finalize.sh           finish bootstrap, shell and app registration
#   ./finalize.sh --check   report state without changing the device
#
# Every mutation is one-time and guarded. In particular, uicache -a must never
# become a per-boot repair: after container applications exist it can classify
# them incorrectly and make them disappear from the home screen.

set -e
cd "${0:A:h}"

# Allow the device's ECDSA key and AES-CTR cipher without dropping SSH defaults.
SSHOPT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
        -o LogLevel=ERROR -o ConnectTimeout=25
        -o HostKeyAlgorithms=+ecdsa-sha2-nistp521 -o Ciphers=+aes128-ctr
        -p "${LITER8_SSH_PORT:-2222}")
DEV="root@${LITER8_SSH_HOST:-localhost}"
PW=alpine
# ssh's own askpass hook rather than sshpass, which races this dropbear's
# password prompt and intermittently sends the wrong secret. The shim keeps the
# `-p <password> ssh|scp ...` call shape, so the call sites below are unchanged.
# Its header has the measurements.
SSHPASS=${0:A:h}/askpass-sshpass
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

RPATH='export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/sbin:/usr/bin:/bin:/usr/sbin:/sbin'
REGISTRATION_MARKER=/var/jb/.liter8-system-apps-registered

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1" }
ok()   { printf '    [+] %s\n' "$1" }
skip() { printf '    [=] %s\n' "$1" }
die()  { printf '    [!] %s\n' "$1"; exit 1 }

sh_dev() { "$SSHPASS" -p "$PW" ssh "${SSHOPT[@]}" "$DEV" "$@" }

[[ -x "$SSHPASS" ]] || die "missing $SSHPASS"
[[ -x setup_shell.sh ]] || die "setup_shell.sh is missing beside finalize.sh"

say "normal-boot connection"

# Reuse an operator-owned forward when one exists. Otherwise Liter8 owns this
# temporary process and reliably stops it on every exit path.
if ! sh_dev 'exit 0' >/dev/null 2>&1; then
    [[ "$DEV" == root@localhost && "${LITER8_SSH_PORT:-2222}" == 2222 ]] \
        || die "cannot reach $DEV on port ${LITER8_SSH_PORT:-2222}"
    command -v iproxy >/dev/null 2>&1 \
        || die "iproxy not found (brew install libimobiledevice)"
    iproxy 2222:22 >/dev/null 2>&1 &
    IPROXY_PID=$!
    trap 'kill "$IPROXY_PID" 2>/dev/null' EXIT
    sleep 2
fi

if ! MOUNTS=$(sh_dev '/sbin/mount' 2>/dev/null); then
    die "SSH handshake with $DEV failed; if Dropbear sends a banner but closes during key exchange, rerun fw provision from SSHRD to generate its host keys"
fi
if print -r -- "$MOUNTS" | grep -q 'md0 on /'; then
    die "device is in SSHRD; finalize requires a normal boot"
fi
ok "normal boot and root SSH"

# Reaching this point proves Dropbear completed key exchange. Check the durable
# reason it can do so, rather than accepting a one-off process state.
sh_dev '[ -s /private/var/dropbear/dropbear_rsa_host_key ] &&
        [ -s /private/var/dropbear/dropbear_ecdsa_host_key ] &&
        [ -s /private/var/dropbear/dropbear_dss_host_key ]' \
    || die "Dropbear connected but one or more per-device host keys are missing"
ok "per-device Dropbear host keys present on Data"

sh_dev "$RPATH; [ -x /var/jb/bin/sh ] && [ -x /var/jb/usr/bin/zsh ]" \
    || die "bootstrap shells are missing under /var/jb"
ok "bootstrap shells present"

bootstrap_complete() {
    sh_dev "$RPATH
        [ ! -e /var/jb/prep_bootstrap.sh ] &&
        [ -s /var/jb/etc/pwd.db ] &&
        [ -s /var/jb/etc/spwd.db ] &&
        grep -q '^root:.*:/var/jb/usr/bin/zsh$' /var/jb/etc/master.passwd &&
        grep -q '^mobile:.*:/var/jb/usr/bin/zsh$' /var/jb/etc/master.passwd" \
        >/dev/null 2>&1
}

say "Procursus bootstrap"
if bootstrap_complete; then
    skip "already finalized"
elif (( CHECK_ONLY )); then
    skip "PENDING: prep_bootstrap.sh has not completed"
    FINALIZE_INCOMPLETE=1
else
    sh_dev "$RPATH; [ -f /var/jb/prep_bootstrap.sh ]" \
        || die "bootstrap is incomplete but prep_bootstrap.sh is absent"

    # The script removes itself. Preserve a retry copy until its concrete
    # outputs have been checked, otherwise an internal failure could leave no
    # way to resume without extracting the entire bootstrap again.
    sh_dev "$RPATH
        cp /var/jb/prep_bootstrap.sh /var/jb/prep_bootstrap.sh.liter8-backup &&
        NO_PASSWORD_PROMPT=1 /var/jb/bin/sh /var/jb/prep_bootstrap.sh" \
        || die "prep_bootstrap.sh failed"

    if ! bootstrap_complete; then
        sh_dev "$RPATH
            [ ! -f /var/jb/prep_bootstrap.sh.liter8-backup ] ||
            cp /var/jb/prep_bootstrap.sh.liter8-backup /var/jb/prep_bootstrap.sh" \
            >/dev/null 2>&1 || true
        die "bootstrap outputs failed verification; retry script was restored"
    fi
    sh_dev "$RPATH; rm -f /var/jb/prep_bootstrap.sh.liter8-backup"
    ok "packages, passwd databases and root/mobile zsh shells configured"
fi

say "root shell profile"
if (( CHECK_ONLY )); then
    if ./setup_shell.sh --check; then
        ok "shell profile complete"
    else
        FINALIZE_INCOMPLETE=1
    fi
else
    ./setup_shell.sh
    ok "shell profile installed and parsed"
fi

# The substrate-compatible names for the hooking library. Provisioning installs
# libellekit.dylib itself as a regular file, hash-verified; these are symlinks
# to it, which is the whole point. A tweak that links libsubstrate.dylib must
# get the *same* image as one that links libellekit.dylib, or the process maps
# two copies of the hooking library with separate state. They are made here and
# not in the ramdisk because ln is not a tool the SSHRD tool set is known to
# have, while a booted Procursus bootstrap certainly does.
#
# DynamicLibraries is the legacy tweak directory; pointing it at TweakInject is
# what upstream's own package does, so a tweak that installs to the old path is
# still found.
#
# Nothing registers this with dpkg. A tweak declaring Depends: mobilesubstrate
# will therefore not install from apt, which is honest: function hooking is
# killed by TXM on this device, so such a tweak would crash its host process
# even if apt let it in. Revisit if that ever changes.
say "substrate compatibility names"
typeset -A EK_LINKS
EK_LINKS=(
    /var/jb/usr/lib/libsubstrate.dylib                                /var/jb/usr/lib/libellekit.dylib
    /var/jb/usr/lib/libhooker.dylib                                   /var/jb/usr/lib/libellekit.dylib
    /var/jb/usr/lib/libblackjack.dylib                                /var/jb/usr/lib/libellekit.dylib
    /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/usr/lib/libellekit.dylib
    /var/jb/usr/lib/TweakInject.dylib                                 /var/jb/usr/lib/ellekit/libinjector.dylib
    /var/jb/Library/MobileSubstrate/DynamicLibraries                   /var/jb/usr/lib/TweakInject
)
if ! sh_dev "$RPATH; [ -f /var/jb/usr/lib/libellekit.dylib ]" >/dev/null 2>&1; then
    skip "libellekit.dylib is not installed; run provisioning's tweaks step first"
else
    EK_WRONG=()
    for link target in ${(kv)EK_LINKS}; do
        actual=$(sh_dev "$RPATH; readlink '$link' 2>/dev/null" | tr -d '\r')
        [[ "$actual" == "$target" ]] || EK_WRONG+=("$link")
    done
    if (( ${#EK_WRONG} == 0 )); then
        skip "all 6 names already point at the right image"
    elif (( CHECK_ONLY )); then
        # ${EK_WRONG[*]:t} would join first and then take one tail, naming a
        # single file however many are wrong. Apply :t per element.
        printf '    [=] %d of 6 names missing or wrong: %s\n' \
            "${#EK_WRONG}" "${${(@)EK_WRONG:t}[*]}"
        FINALIZE_INCOMPLETE=1
    else
        for link target in ${(kv)EK_LINKS}; do
            sh_dev "$RPATH; mkdir -p '${link:h}' && ln -sfn '$target' '$link'" >/dev/null \
                || die "could not link $link"
        done
        # Read every one back rather than trusting ln's exit status: a wrong
        # target here is silent and only shows up as a tweak behaving oddly.
        for link target in ${(kv)EK_LINKS}; do
            actual=$(sh_dev "$RPATH; readlink '$link' 2>/dev/null" | tr -d '\r')
            [[ "$actual" == "$target" ]] \
                || die "$link points at '${actual:-nothing}', expected '$target'"
        done
        ok "6 names linked and read back"
    fi
fi

say "one-time System application registration"
if sh_dev "$RPATH; [ -f '$REGISTRATION_MARKER' ]" >/dev/null 2>&1; then
    skip "already completed"
elif (( CHECK_ONLY )); then
    skip "PENDING: System applications have not been registered by Liter8"
    FINALIZE_INCOMPLETE=1
else
    # A rebuild is proven for the fresh beta-4 System-app population, but it is
    # unsafe after user/container bundles exist. Refuse instead of guessing.
    container_app=$(sh_dev "$RPATH
        find /var/containers/Bundle/Application -mindepth 2 -maxdepth 2 \
            -name '*.app' -print -quit 2>/dev/null" | tr -d '\r')
    [[ -z "$container_app" ]] \
        || die "container app already exists at $container_app; refusing one-time uicache -a"

    sh_dev "$RPATH
        /var/jb/usr/bin/uicache -a &&
        touch '$REGISTRATION_MARKER' && chmod 0644 '$REGISTRATION_MARKER'" \
        || die "System application registration failed"
    ok "System applications registered; completion marker written"
fi

say "automatic boot job"
# Report each prerequisite independently. The old all-or-nothing expression
# blamed the token and persona when only the persistent wallpaper watcher was
# absent, which hid the actual RC failure during first device validation.
boot_job=$(sh_dev "$RPATH
    log=/var/mobile/jbboot.log
    [ -s \"\$log\" ] && grep -q 'persona 99 created' \"\$log\" && echo PERSONA_OK
    [ -s \"\$log\" ] && grep -q 'icon read token ready' \"\$log\" &&
        [ -s /private/var/tmp/sbext.token ] && echo TOKEN_OK
    /bin/ps aux | grep -q '[p]fwatch' && echo WATCHER_OK" \
    2>/dev/null | tr -d '\r')
if print -r -- "$boot_job" | grep -q '^PERSONA_OK$'; then
    ok "persona 99 recorded"
else
    skip "INCOMPLETE: jbboot did not create persona 99"
    FINALIZE_INCOMPLETE=1
fi
if print -r -- "$boot_job" | grep -q '^TOKEN_OK$'; then
    ok "icon read token recorded"
else
    skip "INCOMPLETE: jbboot did not create the icon read token"
    FINALIZE_INCOMPLETE=1
fi
if print -r -- "$boot_job" | grep -q '^WATCHER_OK$'; then
    ok "PosterBoard repair watcher running"
else
    skip "INCOMPLETE: PosterBoard repair watcher is not running"
    FINALIZE_INCOMPLETE=1
fi

if (( CHECK_ONLY )); then
    if (( ${FINALIZE_INCOMPLETE:-0} )); then
        printf '\n    post-boot finalization is incomplete; run without --check\n'
        exit 1
    fi
    printf '\n    post-boot finalization is complete\n'
    exit 0
fi

if (( ${FINALIZE_INCOMPLETE:-0} )); then
    die "persistent setup completed, but the automatic boot job is unhealthy"
fi

# Restart only after every persistent result has been verified. SpringBoard is
# not responsible for SSH, so the remote command should return normally while
# the UI restarts and rereads the rebuilt application database.
say "SpringBoard restart"
sh_dev "$RPATH; /var/jb/usr/bin/killall -9 SpringBoard" \
    || die "could not restart SpringBoard"
ok "SpringBoard restart requested"

printf '\n[+] Liter8 post-boot finalization complete\n'
