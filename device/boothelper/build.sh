#!/bin/sh
# Build l8boot for the System volume (/usr/local/bin), where the com.jbboot job
# can exec it; launchd cannot exec anything under /var/jb. No entitlements.
set -eu

cd "$(dirname "$0")"

LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

xcrun clang -isysroot "$SDK" \
    -arch arm64 -arch arm64e -miphoneos-version-min=15.0 -O2 -Wall -Wextra -Werror \
    -I ../launchdhook l8boot.c -o l8boot
"$LDID" -Icom.liter8.l8boot -S -Cadhoc l8boot

archs=$(lipo -archs l8boot)
case " $archs " in *" arm64 "*) ;; *) echo "[!] l8boot missing arm64" >&2; exit 1;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] l8boot missing arm64e" >&2; exit 1;; esac
codesign -dv l8boot 2>&1 | grep -q 'flags=0x2(adhoc)' || { echo "[!] l8boot is not ad-hoc signed" >&2; exit 1; }
codesign -v l8boot
echo "[+] l8boot: $archs"
