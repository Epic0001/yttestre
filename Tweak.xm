/*
 *  YTKActivator — Substrate-FREE YTKPlus activator
 *
 *  Strategy (5.6.1):
 *    1. Pre-seed real keychain values so YTKPlus reads them via its own
 *       dlsym-resolved SecItemCopyMatching → activated path is taken
 *    2. ObjC swizzles for settings page bypass and license-alert suppression
 *
 *  No CydiaSubstrate, no fishhook, no DYLD_INTERPOSE — all of those caused
 *  recursion or hangs on 5.6.1. Pure pre-seed + swizzle.
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <objc/message.h>

// ============================================================
#pragma mark — Logging
// ============================================================
#define LOG(fmt, ...) NSLog(@"[YTKActivator] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark — Constants
// ============================================================
static NSString *const kService      = @"me.ikghd.ytkplus.secure";
static NSString *const kVersionKey   = @"com.itzzace.ytkactivator.version";
static NSString *const kVersion      = @"1.0";
static BOOL ytkPlusFound = NO;

static NSString *const kAuthEmail        = @"auth_email_secure";
static NSString *const kAuthLicense      = @"auth_license_secure";
static NSString *const kAuthDevice       = @"auth_device_secure";
static NSString *const kAuthExpires      = @"auth_expires_secure";
static NSString *const kAuthSessionToken = @"auth_session_token";
static NSString *const kAuthTimestamp    = @"auth_timestamp";
static NSString *const kAuthSeal         = @"auth_integrity_seal";
static NSString *const kAuthLastSeal     = @"auth_last_verified_seal";
static NSString *const kEnabledStatus    = @"Enabledytk_status";
static NSString *const kActivationLogged = @"activation_logged";
static NSString *const kStatsSent        = @"stats_sent_before";
static NSString *const kActivationLoggedForKey = @"activation_logged_for_key";
static NSString *const kLastStatsVersion       = @"lastStatsReportedVersion";
static NSString *const kAuthStatusSecure       = @"auth_status_secure";
static NSString *const kYTKVersion             = @"5.6.1";
static NSString *const kFakeLicense            = @"ACTIVATED-0000-0000";

// ============================================================
#pragma mark — Real SecItem pointers (resolved via dlsym, used only by us)
// ============================================================
// We call these directly to write our pre-seed values. We do NOT hook the
// public symbols — see comment block further down for why.
static OSStatus (*real_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*real_SecItemDelete)(CFDictionaryRef) = NULL;
static OSStatus (*real_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;

static void resolveRealSecItem(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_NOLOAD);
        if (!sec) sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);
        if (sec) {
            real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(sec, "SecItemCopyMatching");
            real_SecItemDelete       = (OSStatus (*)(CFDictionaryRef))dlsym(sec, "SecItemDelete");
            real_SecItemAdd          = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(sec, "SecItemAdd");
        }
        if (!real_SecItemCopyMatching)
            real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemCopyMatching");
        if (!real_SecItemDelete)
            real_SecItemDelete = (OSStatus (*)(CFDictionaryRef))dlsym(RTLD_NEXT, "SecItemDelete");
        if (!real_SecItemAdd)
            real_SecItemAdd = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemAdd");
    });
}

// ============================================================
// REMOVED: SecItem interpose hooks
// ============================================================
// Crash analysis showed infinite recursion through hook_SecItemCopyMatching:
//   __CFStringEqual -> -[__NSCFString isEqual:] -> -[__NSDictionaryI objectForKeyedSubscript:]
//   -> YTKActivator+0x4080 -> YTKActivator+0x40E8 (~1000 frames -> stack overflow)
//
// Why: YTKPlus 5.6.1 resolves SecItem* via dlsym(RTLD_DEFAULT, ...) into a
// global function pointer (decomp DAT_017ea610, DAT_017ead30, DAT_017eb308,
// DAT_017eb310). DYLD_INTERPOSE only patches lazy/non-lazy stubs in the GOT,
// NOT runtime-resolved dlsym lookups. So:
//   1. YTKPlus's dlsym call inside Security.framework returns the real address
//   2. But our DYLD_INTERPOSE redirects YouTube's own GOT for SecItemCopyMatching
//   3. real_SecItemCopyMatching (resolved via dlsym(RTLD_NEXT, ...)) ends up
//      pointing back at our hook on this build, causing the loop.
//
// Solution: drop the interpose hooks entirely. They were only "belt and
// suspenders" — the primary mechanism is the keychain pre-seed, which writes
// real values that any caller (YTKPlus or Security.framework directly) reads.
// Without the hooks, no recursion is possible.

// ============================================================
#pragma mark — ObjC swizzle helper
// ============================================================
static BOOL swizzleInstanceMethod(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP prev = method_setImplementation(m, newImp);
    if (origOut) *origOut = prev;
    return YES;
}

// ============================================================
#pragma mark — Alert suppression
// ============================================================
static void (*orig_presentVC)(id, SEL, id, BOOL, id) = NULL;

// Re-entrancy guard. Other tweaks loaded in-process (Choicy, Satella, etc.)
// also swizzle presentViewController:animated:completion:, and the chain of
// "previous IMPs" can loop back to us via objc_msgSend, blowing the stack.
// Crash on 5.6.1 device showed ~1000 recursive frames here.
static _Thread_local int gPresentVCDepth = 0;

static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if (gPresentVCDepth > 0) {
        // Already inside our hook on this thread — don't re-filter, just call
        // through. method_setImplementation returns the *previous* IMP, but
        // calling it routes back through objc_msgSend → the current IMP (us).
        // Bail out via objc_msgSendSuper-equivalent: we can't easily get the
        // real original here, so just no-op to break the loop.
        return;
    }
    gPresentVCDepth++;
    @try {
        if ([vc isKindOfClass:[UIAlertController class]]) {
            UIAlertController *alert = (UIAlertController *)vc;
            NSString *title   = alert.title   ?: @"";
            NSString *message = alert.message ?: @"";
            if ([title containsString:@"license_verification"] ||
                [title containsString:@"verification_passed"] ||
                [message containsString:@"Invalid key"] ||
                [message containsString:@"Invalid signature"] ||
                [message containsString:@"license_expired"] ||
                [message containsString:@"License Options"]) {
                LOG(@"Suppressed license alert");
                return;
            }
        }
        if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
    } @finally {
        gPresentVCDepth--;
    }
}

// ============================================================
#pragma mark — Settings page bypass
// ============================================================
static void hook_settingsVerifyYkChecker(id self, SEL _cmd, id sender) {
    Class rootOptsClass = NSClassFromString(@"RootOptionsController");
    if (!rootOptsClass) return;
    UITableViewController *vc = [[rootOptsClass alloc] initWithStyle:UITableViewStyleGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:nav animated:YES completion:nil];
}

static void hook_openCheckLicense(id self, SEL _cmd) {
    hook_settingsVerifyYkChecker(self, _cmd, nil);
}

// ============================================================
#pragma mark — Force settings cells to show "Active"
// ============================================================
static void forceCellActive(UITableViewCell *cell) {
    if (!cell) return;
    if ([cell.accessoryView isKindOfClass:[UISwitch class]]) {
        UISwitch *sw = (UISwitch *)cell.accessoryView;
        [sw setOn:YES animated:NO];
        sw.enabled = YES;
    }
    NSMutableArray *queue = [NSMutableArray arrayWithObject:cell];
    while (queue.count > 0) {
        UIView *v = queue.firstObject;
        [queue removeObjectAtIndex:0];
        for (UIView *sub in v.subviews) [queue addObject:sub];
        if ([v isKindOfClass:[UISwitch class]]) {
            [(UISwitch *)v setOn:YES animated:NO];
            ((UISwitch *)v).enabled = YES;
        }
        if ([v isKindOfClass:[UILabel class]]) {
            UILabel *lbl = (UILabel *)v;
            NSString *lower = (lbl.text ?: @"").lowercaseString;
            if ([lower containsString:@"inactive"] ||
                [lower containsString:@"verify license"] ||
                [lower containsString:@"not verified"] ||
                [lower containsString:@"disabled"] ||
                [lower containsString:@"not active"]) {
                lbl.text = @"Active";
                lbl.textColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.2 alpha:1.0];
            }
        }
    }
}

static void (*orig_configureEnabledCell)(id, SEL, id) = NULL;
static void hook_configureEnabledCell(id self, SEL _cmd, id cell) {
    if (orig_configureEnabledCell) orig_configureEnabledCell(self, _cmd, cell);
    if ([cell isKindOfClass:[UITableViewCell class]]) {
        forceCellActive((UITableViewCell *)cell);
        dispatch_async(dispatch_get_main_queue(), ^{
            forceCellActive((UITableViewCell *)cell);
        });
    }
}

static UITableViewCell *(*orig_cellForRow)(id, SEL, UITableView *, NSIndexPath *) = NULL;
static UITableViewCell *hook_cellForRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    UITableViewCell *cell = orig_cellForRow ? orig_cellForRow(self, _cmd, tv, ip) : nil;
    forceCellActive(cell);
    return cell;
}

// ============================================================
#pragma mark — Keychain pre-seed
// ============================================================
static void writeKeychainValue(NSString *account, NSString *value) {
    resolveRealSecItem();
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    real_SecItemDelete((__bridge CFDictionaryRef)delQuery);
    if (!value) return;
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass:         (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:   kService,
        (__bridge id)kSecAttrAccount:   account,
        (__bridge id)kSecValueData:     [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    real_SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
}

static void preseedKeychain(void) {
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(kEnabledStatus,    @"1");
    writeKeychainValue(kActivationLogged, @"1");
    writeKeychainValue(kStatsSent,        @"1");
    writeKeychainValue(kAuthEmail,        @"activated@ytk.local");
    writeKeychainValue(kAuthLicense,      kFakeLicense);
    writeKeychainValue(kAuthDevice,       @"YTKActivator");
    writeKeychainValue(kAuthExpires,      @"01-01-2030 12:00 AM");
    writeKeychainValue(kAuthSessionToken, @"YTKActivator-Token");
    writeKeychainValue(kAuthTimestamp,    @"9999999999");

    // Skip server-side activation: YTKPlus only POSTs to ikghd.site when
    // activation_logged_for_key != auth_license_secure. Match them so the
    // call never fires (decomp FUN_0003db08 line 33321).
    writeKeychainValue(kActivationLoggedForKey, kFakeLicense);

    // Skip server-side stats: YTKPlus only POSTs when lastStatsReportedVersion
    // != current tweak version (decomp FUN_0003d334 line 33173).
    writeKeychainValue(kLastStatsVersion, kYTKVersion);

    // Mark auth as already verified so detectModification's caller branches
    // into the "authenticated" path (decomp line 33191).
    writeKeychainValue(kAuthStatusSecure, @"1");

    // Leave seal keys alone — 5.6.1's detectModification only checks for
    // FridaGadget in dyld images, NOT seal validity. Deleting the seal was
    // what triggered "incompatible environment" on 5.6.1.
}

// ============================================================
#pragma mark — First-launch welcome popup
// ============================================================
static void showWelcomeIfNeeded(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *lastVersion = [defaults stringForKey:kVersionKey];

    if ([lastVersion isEqualToString:kVersion]) return; // already shown

    [defaults setObject:kVersion forKey:kVersionKey];
    [defaults synchronize];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"YTKActivator"
            message:@"YTKPlus has been activated.\n\nAll premium features are now enabled.\n\nMade by itzzace"
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                          style:UIAlertActionStyleCancel handler:nil]];

        UIWindowScene *ws = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
        }
        UIViewController *topVC = nil;
        for (UIWindow *w in ws.windows) {
            if (w.isKeyWindow) { topVC = w.rootViewController; break; }
        }
        while (topVC.presentedViewController) topVC = topVC.presentedViewController;
        if (topVC) {
            if (orig_presentVC) {
                orig_presentVC(topVC, @selector(presentViewController:animated:completion:),
                               alert, YES, nil);
            } else {
                [topVC presentViewController:alert animated:YES completion:nil];
            }
        }
    });
}

// ============================================================
#pragma mark — Dyld image callback
// ============================================================
static void dyld_callback(const struct mach_header *mh, intptr_t slide) {
    @try {
        Dl_info info;
        if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;
        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        if (![path containsString:@"YTKPlus"]) return;

        ytkPlusFound = YES;
        LOG(@"YTKPlus detected");

        // Wait for runtime classes, then install ObjC swizzles
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            // Settings page bypass
            Class dc = NSClassFromString(@"DownloadsController");
            if (dc) {
                IMP ign = NULL;
                swizzleInstanceMethod(dc, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                      (IMP)hook_settingsVerifyYkChecker, &ign);
                swizzleInstanceMethod(dc, NSSelectorFromString(@"openCheckLicense"),
                                      (IMP)hook_openCheckLicense, &ign);
            }
            Class dc2 = NSClassFromString(@"DownloadsController2");
            if (dc2) {
                IMP ign = NULL;
                swizzleInstanceMethod(dc2, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                      (IMP)hook_settingsVerifyYkChecker, &ign);
                swizzleInstanceMethod(dc2, NSSelectorFromString(@"openCheckLicense"),
                                      (IMP)hook_openCheckLicense, &ign);
            }

            // Force settings cells active
            Class roc = NSClassFromString(@"RootOptionsController");
            if (roc) {
                swizzleInstanceMethod(roc, NSSelectorFromString(@"configureEnabledCell:"),
                                      (IMP)hook_configureEnabledCell, (IMP *)&orig_configureEnabledCell);
                swizzleInstanceMethod(roc, @selector(tableView:cellForRowAtIndexPath:),
                                      (IMP)hook_cellForRow, (IMP *)&orig_cellForRow);
            }

            // Welcome popup (first launch only)
            showWelcomeIfNeeded();
        });
    } @catch (NSException *e) {
        LOG(@"dyld_callback exception: %@", e);
    }
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    @try {
        resolveRealSecItem();
        LOG(@"YTKActivator %@ starting", kVersion);

        // Pre-seed on a background queue. Calling SecItem* directly from
        // the constructor blocks the main thread on the keychain daemon's
        // XPC handshake during early launch, which trips the watchdog.
        // Offloading to a bg queue lets the constructor return immediately
        // and the writes still finish well before YTKPlus's
        // application:didFinishLaunchingWithOptions: reads any keys.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            preseedKeychain();
            LOG(@"YTKActivator %@ keychain ready", kVersion);
        });

        // Register dyld callback (catches YTKPlus image load for ObjC swizzles)
        _dyld_register_func_for_add_image(dyld_callback);

        // Alert suppression — safe to swizzle UIViewController immediately,
        // it's already loaded by the time any tweak constructor runs.
        swizzleInstanceMethod([UIViewController class],
                              @selector(presentViewController:animated:completion:),
                              (IMP)hook_presentVC, (IMP *)&orig_presentVC);

        LOG(@"YTKActivator %@ ready", kVersion);
    } @catch (NSException *e) {
        LOG(@"init exception: %@", e);
    }
}
