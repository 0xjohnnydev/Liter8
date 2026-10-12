/*
 * l8persona.dylib - let app installs resolve a persona on the SEP-less boot.
 *
 * An install names the app by an MIAppIdentity. When the client has no
 * persona of its own (the kernel persona table is empty on this boot, so
 * UMUserPersona reports none), MobileInstallation substitutes
 * PersonalPersonaPlaceholderString and resolves it against the personas
 * usermanagerd lists. usermanagerd lists no personal persona here, so
 * -[MIAppIdentity resolvePersonaWithError:] fails and installcoordinationd
 * reports "Client provided invalid persona for <bundle> : <reason>".
 *
 * The same method already has a branch that needs no usermanagerd at all: on
 * a Shared iPad it resolves every identity to CONTAINER_PERSONA_PRIMARY. This
 * tweak takes that branch only after the stock resolution has failed and only
 * while MobileInstallation knows no personal persona, so on a device where
 * personas exist it never changes anything. IXApplicationIdentity (the
 * installcoordinationd subclass) calls super, so one hook covers both daemons.
 *
 * This is an install-path workaround, not a persona fix: the Files app's local
 * provider, and anything else that needs a real personal persona, is
 * unaffected. Whether containermanagerd accepts the primary persona outside
 * Shared iPad is not confirmed on this hardware; the failure mode if it does
 * not is the original install error.
 *
 * The fork this comes from reports an AltStore Marketplace install succeeding
 * on iPadOS 23H30 with this tweak, l8localauth and a disk eligibility edit
 * together. None of that combination is verified on iPhone 11.
 *
 * Scope and safety:
 *   - Dormant unless the root-owned marker /var/jb/.liter8-persona exists, so
 *     it is a runtime kill switch (rm it to restore stock behaviour).
 *   - Only a failed resolution is touched; every success passes through.
 *   - A method swizzle in installd / installcoordinationd (see the plist), so
 *     it needs no code-signing patch.
 *
 * Known imprecision, not yet fixed. The fallback cannot tell "the client named
 * no persona" from "the client named one that does not exist": it keys on the
 * stock call having failed while MobileInstallation knows no personal persona,
 * and on this hardware the second term is always true once the marker is armed.
 * So a client asking for an explicit nonexistent persona has its identity
 * rewritten to the primary container persona and gets success, where the honest
 * answer is the original error. Unlikely to be reached on a single-user iPhone,
 * since nothing in the normal install path names a persona, but it is wrong.
 *
 * Narrowing it needs one fact this code cannot read: whether the placeholder
 * lands in the identity before it is constructed or inside the stock resolve.
 * PersonalPersonaPlaceholderString is a string in InstalledContentLibrary and
 * not an exported symbol, so it cannot be looked up the way
 * CONTAINER_PERSONA_PRIMARY is. The log line below carries personaUniqueString
 * from either side of the stock call so one armed install settles it.
 *
 * Install as an ElleKit tweak: l8persona.dylib and l8persona.plist in
 * /var/jb/usr/lib/TweakInject. Build: device/personafix/build.sh.
 */

#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <mach-o/loader.h>
#include <os/log.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>

#ifndef L8_PERSONA_MARKER
#define L8_PERSONA_MARKER "/private/var/jb/.liter8-persona"
#endif
#ifndef L8_PERSONA_OWNER
#define L8_PERSONA_OWNER 0 /* root */
#endif
/* Overridable only so the host self-test can use stand-ins: macOS ships its
 * own InstalledContentLibrary with classes of the same names. */
#ifndef L8_IDENTITY_CLASS
#define L8_IDENTITY_CLASS "MIAppIdentity"
#endif
#ifndef L8_USERMGMT_CLASS
#define L8_USERMGMT_CLASS "MIUserManagement"
#endif
#ifndef L8_PRIMARY_SYMBOL
#define L8_PRIMARY_SYMBOL "CONTAINER_PERSONA_PRIMARY"
#endif

typedef BOOL (*ResolveIMP)(id, SEL, NSError **);
static ResolveIMP gOriginalResolve;

static BOOL marker_enabled(void) {
    struct stat st;
    if (lstat(L8_PERSONA_MARKER, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && st.st_uid == (uid_t)(L8_PERSONA_OWNER) &&
           (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* MobileInstallation's own view: no personal persona was discovered. */
static BOOL no_personal_persona(void) {
    Class management = objc_lookUpClass(L8_USERMGMT_CLASS);
    SEL shared = sel_registerName("sharedInstance");
    SEL primary = sel_registerName("primaryPersonaUniqueString");
    if (management == Nil || ![management respondsToSelector:shared]) return NO;
    id instance = ((id (*)(id, SEL))objc_msgSend)(management, shared);
    if (instance == nil || ![instance respondsToSelector:primary]) return NO;
    return ((id (*)(id, SEL))objc_msgSend)(instance, primary) == nil;
}

/* The containermanager constant the Shared iPad branch uses. */
static NSString *primary_container_persona(void) {
    const char *const *symbol = dlsym(RTLD_DEFAULT, L8_PRIMARY_SYMBOL);
    if (symbol == NULL || *symbol == NULL) return nil;
    return [NSString stringWithUTF8String:*symbol];
}

/* Read a string-valued accessor by name. For logging only, so a class without
 * it must not be fatal: MIAppIdentity carries bundleID and personaUniqueString
 * (both appear in InstalledContentLibrary, alongside
 * -[MIAppIdentity _doInitWithBundleID:personaUniqueString:location:]), but
 * neither is a published interface. */
static NSString *string_property(id object, const char *name) {
    SEL selector = sel_registerName(name);
    if (![object respondsToSelector:selector]) return nil;
    id value = ((id (*)(id, SEL))objc_msgSend)(object, selector);
    return [value isKindOfClass:[NSString class]] ? (NSString *)value : nil;
}

static BOOL l8_resolve(id self, SEL sel, NSError **error) {
    /* Read before the stock call, because that call is what may substitute a
     * persona. The pair settles the one open question about this hook: whether
     * MobileInstallation puts PersonalPersonaPlaceholderString in the identity
     * before constructing it or inside resolvePersonaWithError:.
     *
     * It matters because the fallback below cannot currently tell "the client
     * named no persona" from "the client named one that does not exist", and
     * only the first should be rewritten. Which value carries the placeholder
     * decides how to narrow it, and the placeholder is not an exported symbol
     * so it cannot simply be looked up. */
    NSString *named_before = string_property(self, "personaUniqueString");
    NSError *native = nil;
    BOOL ok = gOriginalResolve(self, sel, &native);
    if (ok || !marker_enabled() || !no_personal_persona()) {
        if (error) *error = native;
        return ok;
    }
    /* Read before the mutation further down overwrites it. */
    NSString *named_after = string_property(self, "personaUniqueString");
    NSString *bundle = string_property(self, "bundleID");
    NSString *persona = primary_container_persona();
    SEL setPersona = sel_registerName("setPersonaUniqueString:");
    SEL setResolved = sel_registerName("setIsResolved:");
    if (persona == nil || ![self respondsToSelector:setPersona] ||
        ![self respondsToSelector:setResolved]) {
        /* Silent before. A nil CONTAINER_PERSONA_PRIMARY left the stock failure
         * in place and logged nothing, so a boot where the fallback could not
         * run looked exactly like one where it was never needed. */
        os_log_error(OS_LOG_DEFAULT, "l8persona: fallback unavailable bundle=%{public}@ "
                     "primary=%{public}@ setPersona=%d setResolved=%d",
                     bundle, persona, [self respondsToSelector:setPersona],
                     [self respondsToSelector:setResolved]);
        if (error) *error = native;
        return ok;
    }
    ((void (*)(id, SEL, id))objc_msgSend)(self, setPersona, persona);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(self, setResolved, YES);
    if (error) *error = nil;
    /* [self description] used to stand in for the identity here, but
     * MIAppIdentity defines no description and NSObject's prints the address
     * only, so the log could not answer what the identity actually named. */
    os_log_error(OS_LOG_DEFAULT, "l8persona: fallback bundle=%{public}@ named-before=%{public}@ "
                 "named-after=%{public}@ resolved-to=%{public}@ stock-error=%{public}@",
                 bundle, named_before, named_after, persona, native.localizedDescription);
    return YES;
}

static atomic_bool gInstalled;

static void install_if_ready(void) {
    if (atomic_load(&gInstalled)) return;
    Class cls = objc_lookUpClass(L8_IDENTITY_CLASS);
    if (cls == Nil) return;
    bool expected = false;
    if (!atomic_compare_exchange_strong(&gInstalled, &expected, true)) return;

    Method method = class_getInstanceMethod(cls, sel_registerName("resolvePersonaWithError:"));
    if (method == NULL || method_getNumberOfArguments(method) != 3) {
        os_log_error(OS_LOG_DEFAULT, "l8persona: resolvePersonaWithError: not found (pid %d)", getpid());
        return;
    }
    gOriginalResolve = (ResolveIMP)method_getImplementation(method);
    method_setImplementation(method, (IMP)l8_resolve);
    os_log_error(OS_LOG_DEFAULT, "l8persona: installed in pid %d", getpid());
}

/* Pure header parsing: the objc image-load callback holds the runtime lock,
 * so it must not call into objc (see l8localauth). */
static BOOL is_library_image(const struct mach_header *header) {
    if (header == NULL || header->magic != MH_MAGIC_64) return NO;
    const struct load_command *command =
        (const struct load_command *)((const char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (command->cmd == LC_ID_DYLIB) {
            const struct dylib_command *dylib = (const struct dylib_command *)command;
            const char *name = (const char *)command + dylib->dylib.name.offset;
            return strstr(name, "/InstalledContentLibrary.framework/") != NULL;
        }
        command = (const struct load_command *)((const char *)command + command->cmdsize);
    }
    return NO;
}

static void deferred_install(void *context) {
    (void)context;
    @autoreleasepool { install_if_ready(); }
}

static void image_loaded(const struct mach_header *header) {
    if (atomic_load(&gInstalled) || !is_library_image(header)) return;
    dispatch_async_f(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), NULL,
                     deferred_install);
}

#ifndef LITER8_PERSONA_TEST
__attribute__((constructor))
static void install(void) {
    @autoreleasepool {
        install_if_ready();
        if (!atomic_load(&gInstalled)) objc_addLoadImageFunc(image_loaded);
    }
}
#else
/* Host self-test with stand-ins for the iOS classes and constant. */
const char *L8TestPrimaryPersona = "TestPrimaryPersona";
static id gPrimary;

@interface L8TestUserManagement : NSObject
@end
@implementation L8TestUserManagement
+ (instancetype)sharedInstance { static L8TestUserManagement *s; if (!s) s = [self new]; return s; }
- (id)primaryPersonaUniqueString { return gPrimary; }
@end

@interface L8TestAppIdentity : NSObject
@property (copy, nonatomic) NSString *personaUniqueString;
@property (copy, nonatomic) NSString *bundleID;
@property (nonatomic) BOOL isResolved;
@end
@implementation L8TestAppIdentity
- (BOOL)resolvePersonaWithError:(NSError **)error {
    if (error) *error = [NSError errorWithDomain:@"MIInstallerErrorDomain" code:0xbf userInfo:nil];
    return NO;
}
/* Covers the isKindOfClass guard in string_property: an accessor of the right
 * name whose value is not a string must read as absent, not be returned. */
- (id)location { return @42; }
@end

int main(void) {
    @autoreleasepool {
        (void)image_loaded;
        install_if_ready();
        if (gOriginalResolve == NULL) return 1;
        NSString *marker = @L8_PERSONA_MARKER;
        [[NSFileManager defaultManager] removeItemAtPath:marker error:nil];

        L8TestAppIdentity *identity = [L8TestAppIdentity new];
        NSError *error = nil;
        // Marker absent: stock failure passes through.
        if ([identity resolvePersonaWithError:&error] || error.code != 0xbf) return 2;

        [@"" writeToFile:marker atomically:NO encoding:NSUTF8StringEncoding error:nil];
        chmod(marker.fileSystemRepresentation, 0600);
        // A personal persona exists: still untouched.
        gPrimary = @"personal-uuid";
        error = nil;
        if ([identity resolvePersonaWithError:&error] || identity.isResolved) return 3;
        // No personal persona: falls back to the primary container persona.
        gPrimary = nil;
        // A successful fallback must clear an error left by an earlier call.
        error = [NSError errorWithDomain:@"stale" code:1 userInfo:nil];
        if (![identity resolvePersonaWithError:&error] || error != nil) return 4;
        if (!identity.isResolved || ![identity.personaUniqueString isEqualToString:@"TestPrimaryPersona"]) return 5;

        // What the log line reports. A nil persona and a named one have to be
        // distinguishable, or the measurement this logging exists for cannot be
        // read back off the device.
        L8TestAppIdentity *named = [L8TestAppIdentity new];
        named.personaUniqueString = @"explicit-nonexistent";
        named.bundleID = @"com.example.app";
        if (![string_property(named, "personaUniqueString") isEqualToString:@"explicit-nonexistent"]) return 6;
        if (![string_property(named, "bundleID") isEqualToString:@"com.example.app"]) return 7;
        if (string_property(named, "nosuchaccessor") != nil) return 8;
        if (string_property(named, "location") != nil) return 9;
        L8TestAppIdentity *unnamed = [L8TestAppIdentity new];
        if (string_property(unnamed, "personaUniqueString") != nil) return 10;

        [[NSFileManager defaultManager] removeItemAtPath:marker error:nil];
        puts("PASS: stock result kept with marker off or a personal persona; "
             "falls back to CONTAINER_PERSONA_PRIMARY otherwise; "
             "named and unnamed personas are distinguishable in the log");
        return 0;
    }
}
#endif
