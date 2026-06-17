/*
 *  YTKHelper / YTKActivator v2.8-alert-intercept
 *
 *  v2.6 hung on launch because runtime-wide objc_copyClassList scanning during
 *  early dyld/class registration can burn the whole 20s process-launch budget.
 *  This build keeps targeted swizzle retries, and also intercepts the actual License Options UIAlertController presentation. If the hidden openCheckLicense class cannot be found, the alert interceptor replaces that popup with RootOptionsController.
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define LOG(fmt, ...) NSLog(@"[YTKHelper] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";
static NSString *const kJunkSeal    = @"INVALID-SEAL-FORCE-VERIFY-FAIL";
static NSString *const kFutureTs    = @"9999999999.000";

static NSString *ytk_logPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"YTKHelper-debug.log"];
}

static void ytk_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    LOG(@"%@", msg);
    NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = ytk_logPath();
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) [data writeToFile:path atomically:YES];
    else { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
}

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

    writeKeychainValue(@"ytk_last_contact_ts",     kFutureTs);
    writeKeychainValue(@"ytk_last_contact_seal",   kJunkSeal);
    writeKeychainValue(@"auth_last_verified_ts",   kFutureTs);
    writeKeychainValue(@"auth_last_verified_seal", kJunkSeal);
    writeKeychainValue(@"auth_integrity_seal",     nil);
}

static UIViewController *ytk_topVC(void) {
    UIWindowScene *ws = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
        if ([s isKindOfClass:[UIWindowScene class]] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            ws = (UIWindowScene *)s;
            break;
        }
    }
    if (!ws) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
        }
    }
    UIViewController *top = nil;
    for (UIWindow *w in ws.windows) {
        if (w.isKeyWindow) { top = w.rootViewController; break; }
    }
    if (!top) for (UIWindow *w in ws.windows) { top = w.rootViewController; if (top) break; }
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

static void ytk_presentRootOptions(id self) {
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) { ytk_log(@"open failed: RootOptionsController=nil"); return; }

    id allocated = ((id (*)(id, SEL))objc_msgSend)(roc, sel_registerName("alloc"));
    id vc = ((id (*)(id, SEL, NSInteger))objc_msgSend)(allocated,
                                                       sel_registerName("initWithStyle:"),
                                                       UITableViewStyleGrouped);
    if (!vc) { ytk_log(@"open failed: RootOptionsController init nil"); return; }

    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;

    UIViewController *host = [self isKindOfClass:[UIViewController class]] ? (UIViewController *)self : ytk_topVC();
    if (!host) { ytk_log(@"open failed: no host VC"); return; }

    [host presentViewController:nav animated:YES completion:^{
        ytk_log(@"open success: presented RootOptionsController from %@", NSStringFromClass([host class]));
    }];
}


static void (*orig_presentViewController)(id, SEL, UIViewController *, BOOL, void (^)(void)) = NULL;
static _Thread_local int gPresentDepth = 0;

static BOOL ytk_isLicenseOptionsAlert(UIViewController *vc) {
    if (![vc isKindOfClass:[UIAlertController class]]) return NO;
    UIAlertController *alert = (UIAlertController *)vc;
    NSString *title = (alert.title ?: @"").lowercaseString;
    NSString *message = (alert.message ?: @"").lowercaseString;
    NSMutableString *actions = [NSMutableString string];
    for (UIAlertAction *action in alert.actions) {
        [actions appendFormat:@"%@\n", (action.title ?: @"").lowercaseString];
    }
    NSString *haystack = [NSString stringWithFormat:@"%@\n%@\n%@", title, message, actions];
    return [haystack containsString:@"license options"] ||
           [haystack containsString:@"license option"] ||
           [haystack containsString:@"choose an option"] ||
           [haystack containsString:@"activate new license"] ||
           [haystack containsString:@"restore license"] ||
           [haystack containsString:@"renew license"] ||
           [haystack containsString:@"buy license"] ||
           [haystack containsString:@"license_option"] ||
           [haystack containsString:@"activate_new_license"] ||
           [haystack containsString:@"restore_license"] ||
           [haystack containsString:@"renew_license"] ||
           [haystack containsString:@"buy_license"];
}

static void ytk_presentViewController_hook(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    if (gPresentDepth == 0 && ytk_isLicenseOptionsAlert(vc)) {
        ytk_log(@"intercepted License Options alert from %@", NSStringFromClass([self class]));
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            ytk_presentRootOptions(self);
            if (completion) completion();
        });
        return;
    }

    gPresentDepth++;
    if (orig_presentViewController) {
        orig_presentViewController(self, _cmd, vc, animated, completion);
    }
    gPresentDepth--;
}

static void ytk_installPresentInterceptor(void) {
    Method m = class_getInstanceMethod([UIViewController class], @selector(presentViewController:animated:completion:));
    if (!m) { ytk_log(@"present interceptor failed: method missing"); return; }
    IMP cur = method_getImplementation(m);
    if (cur == (IMP)ytk_presentViewController_hook) {
        ytk_log(@"present interceptor already installed");
        return;
    }
    orig_presentViewController = (void (*)(id, SEL, UIViewController *, BOOL, void (^)(void)))method_setImplementation(m, (IMP)ytk_presentViewController_hook);
    ytk_log(@"present interceptor installed");
}

static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    ytk_log(@"hit openCheckLicense on %@", NSStringFromClass([self class]));
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_presentRootOptions(self); });
}

static BOOL ytk_swizzleClassNamed(NSString *className) {
    Class cls = NSClassFromString(className);
    if (!cls) return NO;
    SEL sel = sel_registerName("openCheckLicense");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP cur = method_getImplementation(m);
    if (cur == (IMP)ytk_openCheckLicense_replacement) return YES;
    method_setImplementation(m, (IMP)ytk_openCheckLicense_replacement);
    ytk_log(@"swizzled %@ openCheckLicense", className);
    return YES;
}

static BOOL ytk_swizzleKnownClasses(void) {
    BOOL any = NO;
    NSArray *names = @[
        @"DownloadsController",
        @"DownloadsController2",
        @"DownloadsVideoController",
        @"DownloadsAudioController",
        @"DownloadsShortController",
        @"TabBarSettingsViewController"
    ];
    for (NSString *name in names) any = ytk_swizzleClassNamed(name) || any;
    return any;
}

static void ytk_retrySwizzle(int attempt) {
    BOOL any = ytk_swizzleKnownClasses();
    BOOL roc = (NSClassFromString(@"RootOptionsController") != nil);
    ytk_log(@"retry %d swizzle any=%@ ROC=%@", attempt, any ? @"YES" : @"NO", roc ? @"YES" : @"NO");
    if (any || attempt >= 30) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_retrySwizzle(attempt + 1); });
}

__attribute__((constructor))
static void init(void) {
    [[NSFileManager defaultManager] removeItemAtPath:ytk_logPath() error:nil];
    ytk_log(@"boot v2.8-alert-intercept constructor entered");

    preseedKeychain();
    ytk_log(@"preseed done");

    ytk_installPresentInterceptor();

    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_retrySwizzle(1);
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_log(@"5s heartbeat reached"); });
}

