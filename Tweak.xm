/*
 *  YTKHelper / YTKActivator v2.3 — preseed + openCheckLicense swizzle
 *
 *  Same v2.2 keychain preseed (force-fail seal verifier, empty banlists),
 *  PLUS a runtime swizzle of -openCheckLicense on every class that declares
 *  it. The new IMP skips the License Options popup and directly presents
 *  RootOptionsController in a UINavigationController — exactly the same
 *  three-call sequence YTKPlus uses on the success path of its URLSession
 *  flow (see decomp 99428-99435).
 *
 *  Why this works:
 *    The gear button's UIAction handler (FUN_b1a8) tries an NSURLSession
 *    request to the YTKPlus license server. On servers/networks where that
 *    fails — or when the keychain identity check fails — it falls through
 *    to -openCheckLicense, which shows the "License Options" popup. By
 *    redirecting -openCheckLicense to the success-path opener, the gear
 *    tap always lands on RootOptionsController regardless of network.
 *
 *  Built twice via GitHub Actions:
 *    - YTKHelper.dylib  (current safe name)
 *    - YTKActivator.dylib (legacy name)
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>

#define LOG(fmt, ...) NSLog(@"[YTKHelper] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";
static NSString *const kJunkSeal    = @"INVALID-SEAL-FORCE-VERIFY-FAIL";
static NSString *const kFutureTs    = @"9999999999.000";

// ============================================================
#pragma mark — Keychain pre-seed
// ============================================================
static void writeKeychainValue(NSString *account, NSString *value) {
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQuery);
    if (!value) return;
    NSDictionary *addQuery = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:     kService,
        (__bridge id)kSecAttrAccount:     account,
        (__bridge id)kSecValueData:       [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible:  (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        (__bridge id)kSecAttrSynchronizable: @NO,
    };
    SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
}

static void preseedKeychain(void) {
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    writeKeychainValue(@"auth_email_secure",    @"activated@ytk.local");
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   @"YTKHelper");
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   @"YTKHelper-Token");
    writeKeychainValue(@"auth_timestamp",       @"9999999999");

    writeKeychainValue(@"activation_logged_for_key", kFakeLicense);
    writeKeychainValue(@"lastStatsReportedVersion",  kYTKVersion);

    writeKeychainValue(@"ytk_rc_cache",            @"{\"bannedUUIDs\":[],\"bannedDylibs\":[]}");
    writeKeychainValue(@"ytk_banned_uuids",        @"[]");
    writeKeychainValue(@"ytk_banned_dylib_names",  @"[]");

    writeKeychainValue(@"ytk_last_contact_ts",   kFutureTs);
    writeKeychainValue(@"ytk_last_contact_seal", kJunkSeal);

    writeKeychainValue(@"auth_last_verified_ts",   kFutureTs);
    writeKeychainValue(@"auth_last_verified_seal", kJunkSeal);

    writeKeychainValue(@"auth_integrity_seal", nil);

    LOG(@"Keychain pre-seeded (v2.3)");
}

// ============================================================
#pragma mark — RootOptionsController opener (success-path replica)
// ============================================================
//
// Replicates decomp lines 99428-99435 exactly:
//
//   Class roc = NSClassFromString(@"RootOptionsController");
//   id vc    = [[roc alloc] initWithStyle:UITableViewStyleGrouped];
//   id nav   = [[UINavigationController alloc] initWithRootViewController:vc];
//   [nav setModalPresentationStyle:UIModalPresentationFullScreen]; // 0
//   [self presentViewController:nav animated:YES completion:nil];
//
// `self` here is the host VC (DownloadsController, DownloadsController2,
// or TabBarSettingsViewController) — whichever one openCheckLicense was
// originally invoked on.

static void ytk_presentRootOptions(id self) {
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) {
        LOG(@"RootOptionsController class missing — cannot open settings");
        return;
    }

    // initWithStyle:1  (UITableViewStyleGrouped)
    id vc = ((id (*)(id, SEL))objc_msgSend)([roc alloc],
                                            sel_registerName("initWithStyle:"));
    // ARC-incompatible: initWithStyle: returns a +1 retained instance via
    // alloc/init, which is what we want — passed straight into nav below
    // and balanced when nav is dismissed.
    id nav = [[UINavigationController alloc] initWithRootViewController:vc];
    [nav setModalPresentationStyle:UIModalPresentationFullScreen];

    UIViewController *host = self;
    if (![host isKindOfClass:[UIViewController class]]) {
        // openCheckLicense is only declared on view controllers, but be
        // defensive — fall back to keyWindow rootVC.
        UIWindowScene *ws = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes)
            if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
        for (UIWindow *w in ws.windows)
            if (w.isKeyWindow) { host = w.rootViewController; break; }
        while (host.presentedViewController) host = host.presentedViewController;
    }

    if (host) {
        [host presentViewController:nav animated:YES completion:nil];
        LOG(@"Presented RootOptionsController on %@", NSStringFromClass([host class]));
    } else {
        LOG(@"No host VC to present RootOptionsController on");
    }
}

// ============================================================
#pragma mark — openCheckLicense swizzle
// ============================================================

static SEL kOpenCheckLicenseSel = NULL;

// Replacement IMP for -[X openCheckLicense]. Signature: void(id, SEL).
static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    LOG(@"-[%@ openCheckLicense] intercepted — opening RootOptionsController",
        NSStringFromClass([self class]));
    ytk_presentRootOptions(self);
}

// Swizzle every class that defines -openCheckLicense to point at our IMP.
// Walking the runtime is needed because YTKPlus declares it on multiple
// host VCs (DownloadsController, DownloadsController2, TabBarSettingsViewController)
// and we don't know which one the user's tap will invoke.
static void ytk_swizzleOpenCheckLicense(void) {
    if (!kOpenCheckLicenseSel) kOpenCheckLicenseSel = sel_registerName("openCheckLicense");

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    if (!classes) {
        LOG(@"objc_copyClassList returned NULL");
        return;
    }

    int swizzled = 0;
    for (unsigned int i = 0; i < classCount; i++) {
        Class cls = classes[i];

        // class_getInstanceMethod walks the inheritance chain, which would
        // double-count subclasses. Use class_copyMethodList to find only
        // methods directly declared on this class.
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        if (!methods) continue;

        for (unsigned int j = 0; j < methodCount; j++) {
            if (method_getName(methods[j]) == kOpenCheckLicenseSel) {
                IMP old = method_setImplementation(methods[j],
                    (IMP)ytk_openCheckLicense_replacement);
                LOG(@"Swizzled -[%s openCheckLicense] (old IMP %p)",
                    class_getName(cls), old);
                swizzled++;
                break;
            }
        }
        free(methods);
    }
    free(classes);

    LOG(@"openCheckLicense swizzle complete — %d class(es) patched", swizzled);

    if (swizzled == 0) {
        // YTKPlus.dylib hasn't been linked yet at constructor time. Register
        // a dyld callback that re-runs the swizzle once each new image lands;
        // YTKPlus.dylib will eventually be one of them.
        LOG(@"No classes matched yet — installing dyld_register_func_for_add_image fallback");
    }
}

// dyld add-image callback — fires for every newly-loaded image. We only
// need to re-attempt the swizzle until it sticks at least once.
static volatile int kSwizzleSucceeded = 0;
static void ytk_addImageCallback(const struct mach_header *mh, intptr_t slide) {
    if (kSwizzleSucceeded) return;

    if (!kOpenCheckLicenseSel) kOpenCheckLicenseSel = sel_registerName("openCheckLicense");
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) return; // YTKPlus classes still not registered

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    if (!classes) return;

    int swizzled = 0;
    for (unsigned int i = 0; i < classCount; i++) {
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(classes[i], &methodCount);
        if (!methods) continue;
        for (unsigned int j = 0; j < methodCount; j++) {
            if (method_getName(methods[j]) == kOpenCheckLicenseSel) {
                method_setImplementation(methods[j],
                    (IMP)ytk_openCheckLicense_replacement);
                LOG(@"[dyld-cb] Swizzled -[%s openCheckLicense]",
                    class_getName(classes[i]));
                swizzled++;
                break;
            }
        }
        free(methods);
    }
    free(classes);

    if (swizzled > 0) {
        kSwizzleSucceeded = 1;
        LOG(@"[dyld-cb] swizzle landed (%d classes)", swizzled);
    }
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();
    LOG(@"YTKHelper v2.3 loaded");

    // Try the swizzle now. If YTKPlus.dylib isn't loaded yet (load-order
    // dependent in injected IPAs), the dyld callback will catch it.
    ytk_swizzleOpenCheckLicense();
    if (NSClassFromString(@"RootOptionsController") != nil) {
        kSwizzleSucceeded = 1;
    } else {
        _dyld_register_func_for_add_image(ytk_addImageCallback);
        LOG(@"Registered dyld add-image callback for late YTKPlus load");
    }
}
