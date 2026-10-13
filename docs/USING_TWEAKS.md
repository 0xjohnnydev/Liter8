# Using the tweak loader

ElleKit is registered with dpkg, so a package declaring `Depends: mobilesubstrate`
configures and PreferenceLoader panes render.

ObjC hooks (`%hook`) work on any boot. C function hooks (`MSHookFunction`,
`%hookf`, `EKHook`) need a boot built with `fw get-boot --tweaks`: stock TXM refuses
to let a patched code page execute again, and `--tweaks` builds TXM that allows it.

| works | doesn't |
|---|---|
| `%hook`, `MSHookMessageEx` | C hooks on a boot built without `--tweaks` |
| `MSHookFunction` / `%hookf` on a `--tweaks` boot | C hooks on tiny functions (see below) |
| PreferenceLoader panes, AppSync | |

Tiny functions: ElleKit needs 4 instructions before the target's first `ret` or
`b` to fit its jump. Shorter ones (`mov ; ret`, one-line wrappers) get a jump that
cannot reach the tweak, and the host crashes.

Signing: Theos signs tweaks `flags=0x0`, which SpringBoard silently refuses to
load here. `fw finalize` installs a dpkg hook that re-signs TweakInject dylibs
ad-hoc after every install, so repo tweaks work as-is. Your own Theos builds can
skip that with `<TweakName>_CODESIGN_FLAGS = -S -Cadhoc` in the Makefile.

Two of the shipped tweaks sit dormant until their marker exists:

```sh
# passcode prompts
ssh -p 2222 root@localhost \
  'touch /var/jb/.liter8-localauth && chmod 644 /var/jb/.liter8-localauth'

# app installs
ssh -p 2222 root@localhost \
  'touch /var/jb/.liter8-persona && chmod 644 /var/jb/.liter8-persona'
```

- `.liter8-localauth` translates the SEP-less ACM `-3` failure into "passcode not
  set", so passcode prompts stop hard-failing
- `.liter8-persona` lets app installs resolve a persona

Both must be root-owned and not group or world writable, or the tweak ignores them.
Remove the file to turn either off.

Three things to remember:

1. Injection is session-bound. A reboot disables it. Every boot: `lhookctl enable`.
2. Tweaks on the Data volume are free to change: drop a dylib and plist in
   `/var/jb/usr/lib/TweakInject/` and respawn the target. No DFU needed.
3. Anything in `/usr/lib` or `/sbin` costs a DFU cycle, because the System volume
   is sealed once booted.
