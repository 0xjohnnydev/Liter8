# Using the tweak loader

ElleKit is registered with dpkg, so a package declaring `Depends: mobilesubstrate`
configures and PreferenceLoader panes render.

TXM kills C function hooking. ObjC method swizzling works fine.

| works | doesn't |
|---|---|
| tweaks that swizzle ObjC methods | anything calling `MSHookFunction` / `EKHook` on a C function |
| PreferenceLoader panes, AppSync | inline patches to libSystem/dyld internals |
| anything using `%hook` on a class | `%hookf` |

Apply that filter before installing from a repo. A tweak that crash-loops its host
is almost certainly doing function hooking.

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
