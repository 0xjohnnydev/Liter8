#!/usr/bin/env python3
"""Compile the real gate/controller and exercise persistent flags on macOS."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "device/launchdhook"
with tempfile.TemporaryDirectory(prefix="l8-lhook-session-") as work:
    work = pathlib.Path(work)
    marker = work / "enabled"
    ctl, probe = work / "lhookctl", work / "probe"
    flags = ["-Wall", "-Wextra", "-Werror", f'-DLHOOK_ENABLE_PATH="{marker}"', "-I", str(SRC)]
    subprocess.run(["xcrun", "clang", *flags, str(SRC / "lhookctl.c"), "-o", str(ctl)], check=True)
    source = work / "probe.c"
    source.write_text('#include "lhook_session.h"\nint main(void) { return !lhook_session_enabled(); }\n')
    subprocess.run(["xcrun", "clang", *flags, str(source), "-o", str(probe)], check=True)

    def enabled():
        return subprocess.run([str(probe)]).returncode == 0

    assert not enabled(), "absent flag must disable"
    marker.touch()
    assert not enabled(), "legacy empty flag must disable"
    subprocess.run([str(ctl), "enable"], check=True)
    assert enabled(), "controller must authorize current session"
    current = marker.read_bytes()
    assert len(current) == 36 and marker.stat().st_mode & 0o777 == 0o644
    marker.write_bytes(current + b"\n")
    assert enabled(), "sysctl redirection newline must be accepted"
    for invalid in [b"invalid", current + b"garbage", b"00000000-0000-0000-0000-000000000000", bytes(64)]:
        marker.write_bytes(invalid)
        assert not enabled(), "old boot or malformed flag must disable"
    subprocess.run([str(ctl), "enable"], check=True)
    assert enabled()
    subprocess.run([str(ctl), "disable"], check=True)
    assert not marker.exists() and not enabled()
    subprocess.run([str(ctl), "disable"], check=True)
    print("PASS: absent, legacy, malformed, previous-session flags; enable/disable; readable atomic marker")
