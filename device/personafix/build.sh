#!/bin/sh
# Build l8persona.dylib, the install-path persona fallback for the SEP-less
# boot, plus run its host self-test. Ad-hoc signed; no get-task-allow (AMFI
# SIGKILLs an ad-hoc binary carrying it). No entitlement: it swizzles one
# Objective-C method inside installd and installcoordinationd.
set -e
cd "$(dirname "$0")"
LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

# Self-test on the host first, with stand-in classes: macOS ships its own
# InstalledContentLibrary with classes of the same names, so the test names its
# own. The marker owner becomes the invoking user so the test needs no root.
if command -v clang >/dev/null 2>&1 && [ "$(uname)" = Darwin ]; then
    marker="$(mktemp -u /tmp/l8persona-marker.XXXXXX)"
    xcrun clang -DLITER8_PERSONA_TEST -DL8_PERSONA_MARKER="\"$marker\"" \
        -DL8_PERSONA_OWNER="getuid()" -DL8_IDENTITY_CLASS='"L8TestAppIdentity"' \
        -DL8_USERMGMT_CLASS='"L8TestUserManagement"' \
        -DL8_PRIMARY_SYMBOL='"L8TestPrimaryPersona"' \
        -framework Foundation l8persona.m -o .l8persona-test
    ./.l8persona-test
    rm -f .l8persona-test "$marker"
fi

xcrun clang -isysroot "$SDK" -arch arm64 -arch arm64e \
    -miphoneos-version-min=15.0 -O2 -Wall -Wextra -dynamiclib \
    -Wl,-not_for_dyld_shared_cache -install_name /var/jb/usr/lib/TweakInject/l8persona.dylib \
    -framework Foundation l8persona.m -o l8persona.dylib
# The filter reaches only installd and installcoordinationd, but the tweak still
# links nothing beyond Foundation: MIAppIdentity is resolved by name at runtime.
otool -L l8persona.dylib | grep -q InstalledContentLibrary \
    && { echo "[!] l8persona links InstalledContentLibrary" >&2; exit 1; }
"$LDID" -S -Icom.liter8.l8persona -Cadhoc l8persona.dylib
codesign -d --entitlements :- l8persona.dylib 2>/dev/null | grep -q get-task-allow \
    && { echo "[!] l8persona carries get-task-allow, AMFI will kill it"; exit 1; }
echo "[+] l8persona.dylib  $(wc -c < l8persona.dylib | tr -d ' ') bytes"
