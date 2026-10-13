#!/usr/bin/env python3
"""Compile the real l8boot on macOS with redirected paths and exercise it.

Covers the SSH PATH links, including what is already sitting in a
world-writable /tmp, and the lhook auto-enable opt-in. Ownership by another
account cannot be produced without root, so ownership is checked against the
running user here and against root on the device.
"""
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "device/boothelper/l8boot.c"
SESSION = ROOT / "device/launchdhook"

with tempfile.TemporaryDirectory(prefix="l8-boot-") as work:
    work = pathlib.Path(work)
    tmp, jb = work / "tmp", work / "jb"
    for d in (tmp, jb / "usr/bin", jb / "usr/sbin"):
        d.mkdir(parents=True)
    usr_bin, usr_sbin = str(jb / "usr/bin"), str(jb / "usr/sbin")
    marker, flag = jb / ".lhook_autoenable", jb / ".lhook_enabled"
    binary = work / "l8boot"
    defines = {
        "L8BOOT_TMP": str(tmp), "L8BOOT_USR_BIN": usr_bin, "L8BOOT_USR_SBIN": usr_sbin,
        "L8BOOT_AUTO_MARKER": str(marker), "LHOOK_ENABLE_PATH": str(flag),
        # pid 1 has been up far longer than the settle time, and must never be
        # killed, so the restart is compiled out here.
        "L8BOOT_SB_NAME": "launchd",
    }
    flags = ["-Wall", "-Wextra", "-Werror", "-I", str(SESSION),
             f"-DL8BOOT_OWNER_UID={os.getuid()}", "-DL8BOOT_RESPRING=0"]
    flags += [f'-D{name}="{value}"' for name, value in defines.items()]
    subprocess.run(["xcrun", "clang", *flags, str(SRC), "-o", str(binary)], check=True)

    def run(mode):
        return subprocess.run([str(binary), mode], capture_output=True, text=True)

    def assert_links():
        assert os.readlink(tmp / "bin") == usr_bin
        assert os.readlink(tmp / "usr/bin") == usr_sbin
        st = (tmp / "usr").lstat()
        assert (tmp / "usr").is_dir() and not (tmp / "usr").is_symlink()
        assert st.st_mode & 0o022 == 0, "/tmp/usr must not be group or other writable"

    def displaced(name):
        return sorted(p.name for p in tmp.glob(f"{name}.liter8-displaced.*"))

    assert run("links").returncode == 0
    assert_links()
    assert run("links").returncode == 0 and "linked" not in run("links").stdout, "second run must be a no-op"
    assert not displaced("bin") and not displaced("usr")

    # Something else at /tmp/bin: a planted file, then a link to the wrong place.
    (tmp / "bin").unlink()
    (tmp / "bin").write_text("planted")
    assert run("links").returncode == 0
    assert_links() is None and len(displaced("bin")) == 1
    (tmp / "bin").unlink()
    (tmp / "bin").symlink_to(work)
    assert run("links").returncode == 0
    assert_links() is None and len(displaced("bin")) == 2

    # /tmp/usr replaced by a link, then by a world-writable directory.
    (tmp / "usr/bin").unlink()
    (tmp / "usr").rmdir()
    (tmp / "usr").symlink_to(work)
    assert run("links").returncode == 0
    assert_links() is None and len(displaced("usr")) == 1
    (tmp / "usr").chmod(0o777)
    assert run("links").returncode == 0
    assert_links() is None and len(displaced("usr")) == 2

    # Auto-enable: only for a well-formed opt-in marker, never otherwise.
    assert run("auto").returncode == 0 and not flag.exists(), "absent marker must not enable"
    marker.write_text("")
    marker.chmod(0o666)
    assert run("auto").returncode == 0 and not flag.exists(), "writable marker must not enable"
    marker.chmod(0o644)
    out = run("auto").stdout
    assert "injection enabled for this boot" in out, out
    assert len(flag.read_bytes()) == 36 and flag.stat().st_mode & 0o777 == 0o644
    assert "already enabled" in run("auto").stdout, "second run must not republish"
    print("PASS: PATH links fresh, idempotent and replacing planted entries; "
          "auto-enable only for a well-formed marker")
