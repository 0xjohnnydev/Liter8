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

# ElleKit, installed as its own package on a booted device. This is what brings
# the hooking library, the six substrate compatibility names and, most
# importantly, the dpkg record: without a package declaring it, a tweak whose
# control says Depends: mobilesubstrate cannot be configured, and PreferenceLoader
# and most repo tweaks say exactly that.
#
# It is upstream's deb, unmodified and hash-pinned by fetch_payloads.sh, so
# ElleKit stays ElleKit's in dpkg: its control, its maintainer, its version.
#
# It cannot happen during provisioning. dpkg needs a booted bootstrap, and the
# compatibility names have to be symlinks, which the deb creates and the ramdisk
# has no known ln for. Provisioning installs only the injector and the two
# tweaks, which is enough for injection to work before this step ever runs.
#
# It overwrites the injector and safe-mode payload provisioning installed, with
# upstream's own unsigned copies. Measured: those load and run perfectly well, so
# the overwrite is harmless.
say "ElleKit package"
# Version and digest come from device/ellekit.pin, the same file fetch_payloads.sh
# checked on download.
. ./ellekit.pin
EK_DEB=payload/tweaks/ellekit.deb

# link:target, read out of the package itself rather than guessed:
#   ar x ellekit.deb && xz -dc data.tar.xz | tar tvf -
# lists all seven as symlinks with these targets. The pin carries a digest, so
# a version that changed them could not be installed without bumping the pin.
EK_LINKS=(
    "/var/jb/usr/lib/TweakLoader.dylib:/var/jb/usr/lib/ellekit/libinjector.dylib"
    "/var/jb/usr/lib/TweakInject.dylib:/var/jb/usr/lib/ellekit/libinjector.dylib"
    "/var/jb/usr/lib/libsubstrate.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/usr/lib/libhooker.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/usr/lib/libblackjack.dylib:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate:/var/jb/usr/lib/libellekit.dylib"
    "/var/jb/Library/MobileSubstrate/DynamicLibraries:/var/jb/usr/lib/TweakInject"
)

# What has to be true after this step whether or not it installed anything.
# A finalize interrupted between dpkg registering the package and this running
# leaves the competing boot script in place and the links unchecked, and the
# retry must not accept that state just because dpkg says "installed".
#
# Resolution alone is not the check. `[ -e ]` passed for a link repointed at any
# other existing file: aim TweakLoader.dylib at MobileSafety.dylib and the old
# check reported ElleKit complete while lhook dlopens the wrong image and no
# TweakInject payload loads at all. The target is compared, and a symlink is
# required, so a regular file left where the package wants a link is caught too.
#
# readlink is read once and cached: an absent tool prints nothing, which would
# read as "every target is wrong" instead of "this was not checked".
EK_READLINK=""
ek_broken_links() {
    local bad=() spec link want got
    if [[ -z "$EK_READLINK" ]]; then
        EK_READLINK=$(sh_dev "$RPATH; command -v readlink >/dev/null && echo yes || echo no" | tr -d '\r')
        [[ "$EK_READLINK" == yes ]] \
            || printf '    [!] no readlink on the device PATH; link targets unverified, only resolution\n'
    fi
    for spec in $EK_LINKS; do
        link=${spec%%:*}
        want=${spec#*:}
        if [[ "$EK_READLINK" != yes ]]; then
            sh_dev "$RPATH; [ -e '$link' ]" >/dev/null 2>&1 || bad+=("$link")
            continue
        fi
        got=$(sh_dev "$RPATH; [ -L '$link' ] && [ -e '$link' ] && readlink '$link'" | tr -d '\r')
        [[ "$got" == "$want" ]] || bad+=("$link")
    done
    print -r -- "${bad[@]}"
}
ek_boot_script_present() {
    sh_dev "$RPATH; [ -e /var/jb/etc/rc.d/ellekit-loader ]" >/dev/null 2>&1
}

# Ask for the status, not the version. A removed package keeps its version in
# dpkg's database while its state is "deinstall ok config-files" and every one
# of its files is gone, so a non-empty version means "dpkg has heard of it",
# not "it is installed".
EK_STATE=$(sh_dev "$RPATH; dpkg-query -W -f='\${Version} \${Status}' ellekit 2>/dev/null" | tr -d '\r')
EK_INSTALLED=0
[[ "$EK_STATE" == *"install ok installed"* ]] && EK_INSTALLED=1

if (( EK_INSTALLED )) && [[ "${EK_STATE%% *}" != "$ELLEKIT_VER" ]]; then
    skip "ellekit ${EK_STATE%% *} is installed, but this tree pins $ELLEKIT_VER"
    FINALIZE_INCOMPLETE=1
elif (( EK_INSTALLED )); then
    EK_BAD=(${=$(ek_broken_links)})
    if ek_boot_script_present || (( ${#EK_BAD} )); then
        if (( CHECK_ONLY )); then
            printf '    [=] ellekit %s installed but incomplete: %s\n' "$ELLEKIT_VER" \
                "$(ek_boot_script_present && print -n 'boot script present; ')${EK_BAD:+broken links: ${${(@)EK_BAD:t}[*]}}"
            FINALIZE_INCOMPLETE=1
        else
            sh_dev "$RPATH; rm -f /var/jb/etc/rc.d/ellekit-loader" >/dev/null
            EK_BAD=(${=$(ek_broken_links)})
            if (( ${#EK_BAD} )); then
                # The links are the package's own, so this step cannot recreate
                # them without guessing. Say what is wrong and let the rest of
                # finalize run: nothing after this depends on them.
                printf '    [!] ellekit is installed but these do not resolve: %s\n' \
                    "${${(@)EK_BAD:t}[*]}"
                printf '    [!] reinstall it: dpkg -i /var/root/ellekit.deb on the device\n'
                FINALIZE_INCOMPLETE=1
            else
                ok "ellekit $ELLEKIT_VER already installed; boot script removed, links checked"
            fi
        fi
    else
        skip "ellekit $ELLEKIT_VER already installed and complete"
    fi
elif [[ ! -f "$EK_DEB" ]]; then
    # An absent archive is two different states, and treating both as incomplete
    # made the optional ElleKit download mandatory one stage after provisioning
    # stopped requiring it: with only ellekit.space blocked, fetch and provision
    # both skip the tweak set by design, and `fw finalize` then still exited
    # nonzero with every required bootstrap and boot-job check passing.
    #
    # The loader on the device is what separates them. Present means
    # provisioning installed the tweak stack and the package is still owed:
    # without its dpkg record a tweak declaring Depends: mobilesubstrate cannot
    # be configured. Absent means there is no tweak stack to finish.
    if sh_dev "$RPATH; [ -e /var/jb/usr/lib/TweakLoader.dylib ]" >/dev/null 2>&1; then
        skip "the loader is installed but $EK_DEB is absent; run ./fetch_payloads.sh tweaks"
        skip "until then a tweak needing Depends: mobilesubstrate cannot configure"
        FINALIZE_INCOMPLETE=1
    else
        skip "no tweak stack provisioned and no $EK_DEB; tweak support is off, not unfinished"
    fi
elif (( CHECK_ONLY )); then
    skip "ellekit is not installed; this step would install $EK_DEB"
    FINALIZE_INCOMPLETE=1
else
    # Re-verify the pinned digest here, not only at fetch time. finalize is a
    # separate action that does not rerun the fetch, and this file has sat in a
    # mutable work directory since. dpkg runs maintainer scripts as root, so the
    # thing being handed to it gets checked immediately before the handover.
    EK_GOT_SHA=$(shasum -a 256 "$EK_DEB" | awk '{print $1}')
    [[ "$EK_GOT_SHA" == "$ELLEKIT_SHA" ]] \
        || die "$EK_DEB does not match the pinned digest; refusing to install. got $EK_GOT_SHA"
    sh_dev "$RPATH; tee /var/root/ellekit.deb >/dev/null" < "$EK_DEB" \
        || die "could not copy $EK_DEB to the device"
    # Hash the readback here, not on the device: shasum is not part of the
    # on-device tool set, and a missing tool returns empty rather than failing.
    EK_LANDED=$(sh_dev "$RPATH; cat /var/root/ellekit.deb" | shasum -a 256 | awk '{print $1}')
    [[ "$EK_LANDED" == "$ELLEKIT_SHA" ]] \
        || die "the copy on the device does not match the pinned digest: ${EK_LANDED:-nothing}"
    # Its postinst runs ElleKit's own loader, which asserts and dies here
    # because lhook already owns launchd. dpkg carries on and the install is
    # fine, so the exit status is not the thing to judge this by: ask dpkg.
    sh_dev "$RPATH; dpkg -i /var/root/ellekit.deb 2>&1 | tail -4" | sed 's/^/        /'
    EK_STATE=$(sh_dev "$RPATH; dpkg-query -W -f='\${Version} \${Status}' ellekit 2>/dev/null" | tr -d '\r')
    [[ "$EK_STATE" == *"install ok installed"* ]] \
        || die "ellekit did not register with dpkg: ${EK_STATE:-nothing}"
    [[ "${EK_STATE%% *}" == "$ELLEKIT_VER" ]] \
        || die "dpkg registered ellekit ${EK_STATE%% *}, expected $ELLEKIT_VER"
    # That loader would be run again at every boot for the same assertion, so
    # the boot script goes. dpkg -V will report it missing, which is accurate.
    sh_dev "$RPATH; rm -f /var/jb/etc/rc.d/ellekit-loader" >/dev/null
    EK_BAD=(${=$(ek_broken_links)})
    (( ${#EK_BAD} == 0 )) \
        || die "these do not resolve after installing ellekit: ${${(@)EK_BAD:t}[*]}"
    ok "ellekit $ELLEKIT_VER installed, digest verified; all ${#EK_LINKS} names resolve; boot script removed"
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
