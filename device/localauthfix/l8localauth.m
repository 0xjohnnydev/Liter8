/*
 * l8localauth.dylib - make passcode confirmations succeed on the SEP-less boot.
 *
 * Every "enter your passcode to confirm" prompt (Trust this computer, install a
 * marketplace / alternative app store, authorise a setting) ends in
 * LocalAuthentication asking the Secure Enclave, via ACM, to verify the
 * passcode. With no SEP, ACM returns -3 before any sheet appears, and the app
 * sees com.apple.LocalAuthentication/-1000, which looks like the user cancelled.
 *
 * This is the general form of the per-marketplace workaround from the lhook
 * branch (marketplace-confirmation.m) and of upstream's lockdownd-only
 * l8pair_auth.m. It hooks LAContext in whatever process loads it and, only for
 * the exact SEP-less ACM failure, reports LAErrorPasscodeNotSet instead. That
 * is truthful on this boot (there is no SEP-backed passcode) and sends the UI
 * down its existing no-passcode branch, so the action proceeds. It is not real
 * passcode authorisation; the no-SEP boot cannot produce that.
 *
 * Scope and safety:
 *   - Dormant unless the root-owned marker /var/jb/.liter8-localauth exists, so
 *     it is a runtime kill switch (rm it to restore stock behaviour).
 *   - Translates ONLY the exact ACM -3 / LA -1000 signature. Every success,
 *     every other policy outcome and every other error pass through unchanged.
 *   - Changes no executable pages and needs no task port, so it works whether
 *     or not the code-signing-invalid kernel patches are present.
 *
 * Load it process-wide through lhook (it is an ObjC method swizzle, which the
 * injection path handles without the code-signing patches) or weak-load it into
 * a specific daemon. Build: device/localauthfix/build.sh.
 *
 * Self-test (no device, no injection):
 *   clang -DLITER8_LOCALAUTH_TEST -framework Foundation \
 *       -framework LocalAuthentication l8localauth.m -o t && ./t
 */

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>

#include <os/log.h>
#include <sys/stat.h>
#include <string.h>

typedef void (^Reply)(id result, NSError *error);
typedef void (*EvaluateIMP)(id, SEL, NSInteger, NSDictionary *, Reply);
typedef BOOL (*CanEvaluateIMP)(id, SEL, NSInteger, NSError **);

static EvaluateIMP gOriginalEvaluate;
static CanEvaluateIMP gOriginalCanEvaluate;

static const char *kMarker = "/private/var/jb/.liter8-localauth";

static BOOL marker_enabled(void) {
    struct stat st;
    if (lstat(kMarker, &st) != 0) return NO;
    return S_ISREG(st.st_mode) && st.st_uid == 0 &&
           (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

/* The SEP-less condition, not a specific prompt: ACM could not verify the
 * credential because there is no SEP to verify it against. Matching the
 * signature rather than a policy number is what makes this general across every
 * passcode prompt, while staying narrow enough to leave real failures alone. */
static BOOL is_sep_less_acm_failure(NSError *error) {
    if (error == nil || error.code != -1000 ||
        ![error.domain isEqualToString:@"com.apple.LocalAuthentication"]) {
        return NO;
    }
    id detail = error.userInfo[NSDebugDescriptionErrorKey];
    if (![detail isKindOfClass:[NSString class]]) return NO;
    NSString *text = (NSString *)detail;
    // "ACM verification of <policy> on ACMContext N failed: -3"
    return [text containsString:@"ACM verification"] && [text containsString:@"failed: -3"];
}

static NSError *translated(NSError *error) {
    if (!is_sep_less_acm_failure(error)) return error;
    os_log_error(OS_LOG_DEFAULT,
                 "l8localauth: SEP-less ACM -3 -> passcode-not-set (pid %d)", getpid());
    return [NSError errorWithDomain:LAErrorDomain code:LAErrorPasscodeNotSet userInfo:nil];
}

static void l8_evaluate(id self, SEL sel, NSInteger policy,
                        NSDictionary *options, Reply reply) {
    if (reply == nil || !marker_enabled()) {
        gOriginalEvaluate(self, sel, policy, options, reply);
        return;
    }
    gOriginalEvaluate(self, sel, policy, options, ^(id result, NSError *error) {
        reply(result, result != nil ? error : translated(error));
    });
}

static BOOL l8_canEvaluate(id self, SEL sel, NSInteger policy, NSError **error) {
    NSError *native = nil;
    BOOL ok = gOriginalCanEvaluate(self, sel, policy, &native);
    if (error) *error = (ok || !marker_enabled()) ? native : translated(native);
    return ok;
}

#ifndef LITER8_LOCALAUTH_TEST
__attribute__((constructor))
static void install(void) {
    @autoreleasepool {
        Class cls = objc_lookUpClass("LAContext");
        if (cls == Nil) return;

        SEL evalSel = sel_registerName("evaluatePolicy:options:reply:");
        Method eval = class_getInstanceMethod(cls, evalSel);
        if (eval == NULL || method_getNumberOfArguments(eval) != 5) return;

        SEL canSel = sel_registerName("canEvaluatePolicy:error:");
        Method can = class_getInstanceMethod(cls, canSel);
        if (can == NULL || method_getNumberOfArguments(can) != 4) return;

        gOriginalCanEvaluate = (CanEvaluateIMP)method_setImplementation(can, (IMP)l8_canEvaluate);
        gOriginalEvaluate = (EvaluateIMP)method_setImplementation(eval, (IMP)l8_evaluate);
        os_log_error(OS_LOG_DEFAULT, "l8localauth: installed in pid %d", getpid());
    }
}
#else
int main(void) {
    @autoreleasepool {
        NSError *acm = [NSError errorWithDomain:@"com.apple.LocalAuthentication" code:-1000
            userInfo:@{NSDebugDescriptionErrorKey:
                @"ACM verification of Oslo on ACMContext 0 failed: -3"}];
        NSError *cancel = [NSError errorWithDomain:@"com.apple.LocalAuthentication"
            code:LAErrorUserCancel userInfo:nil];
        NSError *otherMinus1000 = [NSError errorWithDomain:@"com.apple.LocalAuthentication"
            code:-1000 userInfo:nil];
        NSError *wrongDomain = [NSError errorWithDomain:@"other" code:-1000
            userInfo:@{NSDebugDescriptionErrorKey: @"ACM verification failed: -3"}];

        if (translated(acm).code != LAErrorPasscodeNotSet) return 1;
        if (translated(cancel) != cancel) return 2;
        if (translated(otherMinus1000) != otherMinus1000) return 3;
        if (translated(wrongDomain) != wrongDomain) return 4;
        if (translated(nil) != nil) return 5;
        puts("PASS: SEP-less ACM -3 translated; cancellation, other errors and success preserved");
        return 0;
    }
}
#endif
