#!/bin/sh
set -eu

cd "$(dirname "$0")"

LDID=../../tools/ldid_macosx_arm64
"$LDID" -v 2>&1 | grep -q "Link Identity Editor" || LDID=$(command -v ldid || true)
# Command Line Tools have no iPhoneOS SDK. Point LITER8_IOS_SDK at an
# unpacked one (for example Theos's) to build without Xcode.
SDK="${LITER8_IOS_SDK:-$(xcrun --sdk iphoneos --show-sdk-path)}"
[ -d "$SDK" ] || { echo "[!] iOS SDK missing: $SDK" >&2; exit 1; }

xcrun clang -isysroot "$SDK" \
    -arch arm64 -arch arm64e -miphoneos-version-min=26.0 -O2 -Wall -Wextra \
    ddiwatch.c -o ddiwatch
"$LDID" -Icom.liter8.ddiwatch -Sddiwatch.entitlements -Cadhoc ddiwatch

archs=$(lipo -archs ddiwatch)
case " $archs " in *" arm64 "*) ;; *) echo "[!] ddiwatch missing arm64" >&2; exit 1;; esac
case " $archs " in *" arm64e "*) ;; *) echo "[!] ddiwatch missing arm64e" >&2; exit 1;; esac
codesign -v ddiwatch
echo "[+] ddiwatch: $archs"
