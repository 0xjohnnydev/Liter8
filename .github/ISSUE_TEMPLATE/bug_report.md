---
name: Bug report
about: Report a problem with building, restoring, booting, or using Liter8.
title: "[Bug]:"
labels: bug
assignees: ''
type: Bug

---

**Before submitting**

- [ ] I checked the README for supported devices, firmware builds, and known limitations.
- [ ] I searched existing issues for the same problem.

**Describe the bug**

Describe what went wrong and what you were trying to do.

**Device and firmware**

- Device model:
- Board identifier, if known:
- iOS version and exact build number:
- IPSW filename:
- Device state when the issue occurred: [DFU / pwn DFU / SSH ramdisk / booted iOS / other]

**Mac and Liter8 environment**

- macOS version:
- Mac model and chip:
- Liter8 branch and commit:
- Any local code changes:
- USB connection, if relevant: [direct / hub / adapter]

For setup or compilation failures, also include your Xcode Command Line Tools and Swift versions.

**Where does it fail?**

Specify the stage: setup/build, IPSW preparation, CFW creation, restore, ramdisk, provisioning, iOS boot, finalization, or after boot.

- Failing stage:
- Last successful step:
- Work directory: [new / reused from an earlier run]
- If reused, were the artifacts created with a different firmware build or Liter8 commit?

**Steps to reproduce**

List the steps leading to the issue, including any manual changes or retries.

1.
2.
3.

Exact failing command, including all flags:

```sh
Paste the command here.
```

Does this happen every time or intermittently?

**Expected behavior**

Describe what you expected to happen.

**Actual behavior**

Describe what happened instead. Include the terminal error and what the device did, such as a black screen, recovery screen, boot loop, panic, or loss of USB/SSH connectivity.

**Logs and screenshots**

Include terminal output leading up to the failure and the complete error message. Attach a text log if the output is long.

For boot failures or device crashes, include a photo/video of the device screen, a panic log, or UART output if available.

Redact personal device identifiers, credentials, keys, and tickets before posting.

```text
Paste relevant logs here.
```

**Additional context**

- Did this previously work? If so, on which Liter8 commit and iOS build?
- What troubleshooting have you already tried, and what were the results?
- Any custom patches, tweaks, bootstrap changes, or other modifications relevant to the issue?
