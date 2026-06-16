/*
 *  YTKHelper / YTKActivator v2.4-debug — on-screen debug popups
 *
 *  Same v2.3 logic (preseed + openCheckLicense swizzle + dyld fallback)
 *  with verbose UIAlertController popups at every key checkpoint so you
 *  can verify on a glitched device whether the swizzle is actually
 *  installing and intercepting.
 *
 *  Popups you should see, in order:
 *    1. ~2s after launch:  "v2.4-debug: constructor results"
 *         - preseed: done
 *         - classes swizzled at constructor time
 *         - RootOptionsController loaded? YES/NO
 *         - dyld callback: registered or skipped
 *    2. (only if RootOptionsController wasn't loaded at constructor time)
 *       Once YTKPlus.dylib finally loads:
 *         "dyld late-swizzle: N classes patched"
 *    3. When you tap the gear button:
 *         "openCheckLicense INTERCEPTED on <ClassName>"
 *         immediately followed by RootOptionsController presenting.
 *
 *  If you see (1) with classes=0 and RootOptionsController=NO, then
 *  YTKPlus.dylib is loading after us — wait for popup (2). If you NEVER
 *  see popup (3) when you tap gear, the swizzle didn't land on the right
 *  class (or the gear tap goes through a different code path on this
 *  build).
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
#pragma mark — Debug popup plumbing
// ============================================================

static UIViewController *ytk_topVC(void) {
    UIWindowScene *ws = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            ws = (UIWindowScene *)s; break;
        }
    }
    if (!ws) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes)
            if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
    }
    UIViewController *top = nil;
    for (UIWindow *w in ws.windows)
        if (w.isKeyWindow) { top = w.rootViewController; break; }
    if (!top)
        for (UIWindow *w in ws.windows)
            if (top == nil) { top = w.rootViewController; }
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

// Try once to show a popup; returns YES if presented. Main-thread only.
static BOOL ytk_tryShowPopup(NSString *title, NSString *body) {
    UIViewController *host = ytk_topVC();
    if (!host) return NO;
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:title
        message:body
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [host presentViewController:alert animated:YES completion:nil];
    return YES;
}

// Recursive C function — schedules itself on main queue without any
// __block self-capturing block (which is what triggered the
// -Warc-retain-cycles error in v2.4-debug).
static void ytk_popupRetry(NSString *title, NSString *body, int attempt) {
    if (ytk_tryShowPopup(title, body)) return;
    if (attempt >= 20) {
        LOG(@"POPUP gave up after 20 retries: %@", title);
        return;
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_popupRetry(title, body, attempt + 1);
    });
}

// Show a popup. Safe to call from any thread / any time. Defers if UI
// isn't up yet by retrying on main queue every 0.5s up to 20 attempts.
static void ytk_debugPopup(NSString *title, NSString *body) {
    LOG(@"POPUP: %@ — %@", title, body);
    // Capture by value into the block; ytk_popupRetry schedules itself.
    NSString *t = [title copy];
    NSString *b = [body copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_popupRetry(t, b, 1);
    });
}

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

    LOG(@"Keychain pre-seeded (v2.4-debug)");
}

// ============================================================
#pragma mark — RootOptionsController opener
// ============================================================
static void ytk_presentRootOptions(id self) {
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) {
        ytk_debugPopup(@"OPEN FAILED",
            @"RootOptionsController class is NIL at present time.\n"
             "YTKPlus.dylib didn't load, or the class was renamed.");
        return;
    }

    id vc = ((id (*)(id, SEL))objc_msgSend)([roc alloc],
                                            sel_registerName("initWithStyle:"));
    id nav = [[UINavigationController alloc] initWithRootViewController:vc];
    [nav setModalPresentationStyle:UIModalPresentationFullScreen];

    UIViewController *host = self;
    if (![host isKindOfClass:[UIViewController class]]) {
        host = ytk_topVC();
    }

    if (host) {
        [host presentViewController:nav animated:YES completion:nil];
        LOG(@"Presented RootOptionsController on %@", NSStringFromClass([host class]));
    } else {
        ytk_debugPopup(@"OPEN FAILED", @"No host VC available to present from.");
    }
}

// ============================================================
#pragma mark — openCheckLicense swizzle
// ============================================================

static SEL kOpenCheckLicenseSel = NULL;

static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    NSString *cls = NSStringFromClass([self class]);
    LOG(@"-[%@ openCheckLicense] intercepted", cls);
    ytk_debugPopup(@"SWIZZLE HIT",
        ([NSString stringWithFormat:
            @"-[%@ openCheckLicense] intercepted.\n\n"
             "Now presenting RootOptionsController...",
            cls]));
    // Defer the actual present a tick so the debug popup has a chance to
    // appear first. UIAlertController and presentViewController fight if
    // you queue them back-to-back on the same VC.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_presentRootOptions(self);
    });
}

// Returns number of classes whose -openCheckLicense IMP we replaced.
static int ytk_runSwizzlePass(NSMutableString *report) {
    if (!kOpenCheckLicenseSel) kOpenCheckLicenseSel = sel_registerName("openCheckLicense");

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    if (!classes) return 0;

    int swizzled = 0;
    for (unsigned int i = 0; i < classCount; i++) {
        Class cls = classes[i];
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        if (!methods) continue;
        for (unsigned int j = 0; j < methodCount; j++) {
            if (method_getName(methods[j]) == kOpenCheckLicenseSel) {
                method_setImplementation(methods[j],
                    (IMP)ytk_openCheckLicense_replacement);
                if (report) [report appendFormat:@"  - %s\n", class_getName(cls)];
                LOG(@"Swizzled -[%s openCheckLicense]", class_getName(cls));
                swizzled++;
                break;
            }
        }
        free(methods);
    }
    free(classes);
    return swizzled;
}

// ============================================================
#pragma mark — dyld late-swizzle fallback
// ============================================================
static volatile int kSwizzleSucceeded = 0;

static void ytk_addImageCallback(const struct mach_header *mh, intptr_t slide) {
    if (kSwizzleSucceeded) return;

    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) return; // YTKPlus classes still not registered

    NSMutableString *report = [NSMutableString string];
    int swizzled = ytk_runSwizzlePass(report);

    if (swizzled > 0) {
        kSwizzleSucceeded = 1;
        ytk_debugPopup(@"dyld late-swizzle",
            ([NSString stringWithFormat:
                @"YTKPlus.dylib loaded after us.\n"
                 "Late swizzle landed on %d class(es):\n%@",
                swizzled, report]));
    }
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();
    LOG(@"YTKHelper v2.4-debug loaded");

    NSMutableString *classesReport = [NSMutableString string];
    int swizzledNow = ytk_runSwizzlePass(classesReport);
    BOOL rocLoaded  = (NSClassFromString(@"RootOptionsController") != nil);
    BOOL needDyldCb = !rocLoaded || swizzledNow == 0;

    if (rocLoaded && swizzledNow > 0) {
        kSwizzleSucceeded = 1;
    }
    if (needDyldCb) {
        _dyld_register_func_for_add_image(ytk_addImageCallback);
    }

    NSString *body = [NSString stringWithFormat:
        @"v2.4-debug constructor results:\n\n"
         "preseed: DONE\n"
         "classes swizzled now: %d\n%@"
         "RootOptionsController loaded: %@\n"
         "dyld callback: %@\n\n"
         "Tap gear in YTKPlus menu to test. You should see a SWIZZLE HIT popup.",
        swizzledNow,
        (swizzledNow > 0 ? classesReport : @""),
        rocLoaded ? @"YES" : @"NO",
        needDyldCb ? @"REGISTERED" : @"skipped (already done)"];

    // Defer the boot popup until UI is plausibly up.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_debugPopup(@"YTKHelper v2.4-debug", body);
    });
}
