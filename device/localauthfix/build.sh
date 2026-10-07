#!/bin/sh
# Build l8localauth.dylib, the SEP-less passcode-confirmation translator, plus
# run its self-test. Ad-hoc signed; no get-task-allow (AMFI SIGKILLs an ad-hoc
# binary carrying it). No entitlement: it swizzles LAContext in its own process.
set -e
cd "$(dirname "$0")"
LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

# Self-test on the host first: pure translation logic, no device needed.
if command -v clang >/dev/null 2>&1 && [ "$(uname)" = Darwin ]; then
    clang -DLITER8_LOCALAUTH_TEST -framework Foundation \
        -framework LocalAuthentication l8localauth.m -o .l8localauth-test
    ./.l8localauth-test
    rm -f .l8localauth-test
fi

xcrun clang -isysroot "$SDK" -arch arm64 -arch arm64e \
    -miphoneos-version-min=15.0 -O2 -Wall -Wextra -dynamiclib \
    -Wl,-not_for_dyld_shared_cache -install_name /var/jb/usr/lib/TweakInject/l8localauth.dylib \
    -framework Foundation -framework LocalAuthentication \
    l8localauth.m -o l8localauth.dylib
"$LDID" -Icom.liter8.l8localauth -Cadhoc l8localauth.dylib
codesign -d --entitlements :- l8localauth.dylib 2>/dev/null | grep -q get-task-allow \
    && { echo "[!] l8localauth carries get-task-allow, AMFI will kill it"; exit 1; }
echo "[+] l8localauth.dylib  $(wc -c < l8localauth.dylib | tr -d ' ') bytes"
