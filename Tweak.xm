/*
 *  YTKHelper / YTKActivator v2.8-alert-intercept
 *  YTKHelper / YTKActivator v3.0-gated-settings-open
 *
 *  v2.9 reached YTKPlus's real opener, but it silently returned because its
 *  hidden activation gate key was missing. This build asks YTKPlus for that
 *  private key/hash, seeds the gate, logs the clean-scan result, then calls
 *  the real gated opener.
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#define LOG(fmt, ...) NSLog(@"[YTKHelper] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";
static NSString *const kJunkSeal    = @"INVALID-SEAL-FORCE-VERIFY-FAIL";
static NSString *const kFutureTs    = @"9999999999.000";

static const uintptr_t kYTKPrepareSettingsGateOffset = 0x000b7f2c;
static const uintptr_t kYTKOpenSettingsGatedOffset   = 0x000b8000;
static const uintptr_t kYTKReadKeychainOffset        = 0x000b7cd4;
static const uintptr_t kYTKHMACOffset                = 0x000b8840;
static const uintptr_t kYTKSecretOffset              = 0x000b8bbc;
static const uintptr_t kYTKPrivateGateAccountOffset  = 0x000b8dd8;
static const uintptr_t kYTKCleanScanOffset           = 0x000b9128;

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

static NSString *readKeychainValue(NSString *account) {
    if (!account) return nil;
    NSDictionary *query = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:     kService,
        (__bridge id)kSecAttrAccount:     account,
        (__bridge id)kSecReturnData:      @YES,
        (__bridge id)kSecMatchLimit:      (__bridge id)kSecMatchLimitOne,
        (__bridge id)kSecAttrSynchronizable: @NO,
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) return nil;
    NSData *data = CFBridgingRelease(result);
    if (![data isKindOfClass:[NSData class]]) return nil;
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
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

static void *ytk_findYTKPlusAddress(uintptr_t offset) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || !strstr(name, "YTKPlus")) continue;
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;
        return (void *)((uintptr_t)header + offset);
    }
    return NULL;
}

static void *ytk_authFunctionPointer(void *ptr) {
#if __has_feature(ptrauth_calls)
    return ptrauth_sign_unauthenticated(ptr, ptrauth_key_function_pointer, 0);
#else
    return ptr;
#endif
}

static NSString *ytk_callStringFunction(uintptr_t offset, NSString *name) {
    void *ptr = ytk_findYTKPlusAddress(offset);
    if (!ptr) {
        ytk_log(@"private %@ missing at offset 0x%lx", name, (unsigned long)offset);
        return nil;
    }
    typedef id (*YTKStringFn)(void);
    YTKStringFn fn = (YTKStringFn)ytk_authFunctionPointer(ptr);
    id value = fn();
    if (value && ![value isKindOfClass:[NSString class]]) {
        ytk_log(@"private %@ returned non-string %@", name, NSStringFromClass([value class]));
        return nil;
    }
    return value;
}

static NSString *ytk_callHMAC(NSString *data, NSString *key) {
    void *ptr = ytk_findYTKPlusAddress(kYTKHMACOffset);
    if (!ptr || !data || !key) return nil;
    typedef id (*YTKHMACFn)(id, id);
    YTKHMACFn fn = (YTKHMACFn)ytk_authFunctionPointer(ptr);
    id value = fn(data, key);
    if (value && ![value isKindOfClass:[NSString class]]) return nil;
    return value;
}

static NSString *ytk_callYTKRead(NSString *account) {
    void *ptr = ytk_findYTKPlusAddress(kYTKReadKeychainOffset);
    if (!ptr || !account) return nil;
    typedef id (*YTKReadFn)(id);
    YTKReadFn fn = (YTKReadFn)ytk_authFunctionPointer(ptr);
    id value = fn(account);
    if (value && ![value isKindOfClass:[NSString class]]) return nil;
    return value;
}

static void ytk_seedPrivateActivationGate(void) {
    NSString *account = ytk_callStringFunction(kYTKPrivateGateAccountOffset, @"gateAccount");
    NSString *secret = ytk_callStringFunction(kYTKSecretOffset, @"secret");
    NSString *clean = ytk_callStringFunction(kYTKCleanScanOffset, @"cleanScan");
    NSString *existing = account ? readKeychainValue(account) : nil;
    NSString *ytkExisting = account ? ytk_callYTKRead(account) : nil;

    NSString *fullHash = ytk_callHMAC(secret, secret);
    NSString *shortHash = fullHash.length >= 8 ? [fullHash substringToIndex:8] : fullHash;

    ytk_log(@"gate diag account=%@ existing=%@ ytkExisting=%@ shortHash=%@ clean=%@",
            account ?: @"nil",
            existing ?: @"nil",
            ytkExisting ?: @"nil",
            shortHash ?: @"nil",
            clean ?: @"nil");

    if (account.length) {
        writeKeychainValue(account, @"1");
        NSString *after = readKeychainValue(account);
        ytk_log(@"gate seeded %@ -> %@", account, after ?: @"nil");
    }
}

static void ytk_openYTKSettingsViaGatedPath(id self) {
    if (![self isKindOfClass:[UIViewController class]]) {
        UIViewController *top = ytk_topVC();
        ytk_log(@"gated open host remapped %@ -> %@",
                NSStringFromClass([self class]),
                top ? NSStringFromClass([top class]) : @"nil");
        self = top;
    }
    if (!self) {
        ytk_log(@"gated open failed: no host");
        return;
    }

    void *preparePtr = ytk_findYTKPlusAddress(kYTKPrepareSettingsGateOffset);
    void *openPtr = ytk_findYTKPlusAddress(kYTKOpenSettingsGatedOffset);
    if (!preparePtr || !openPtr) {
        ytk_log(@"gated open failed: private funcs missing prepare=%p open=%p", preparePtr, openPtr);
        return;
    }

    typedef void (*YTKPrepareSettingsGateFn)(void);
    typedef void (*YTKOpenSettingsGatedFn)(id);
    YTKPrepareSettingsGateFn prepareGate = (YTKPrepareSettingsGateFn)ytk_authFunctionPointer(preparePtr);
    YTKOpenSettingsGatedFn openSettings = (YTKOpenSettingsGatedFn)ytk_authFunctionPointer(openPtr);

    ytk_log(@"gated open calling prepare=%p open=%p host=%@",
            preparePtr, openPtr, NSStringFromClass([self class]));
    ytk_seedPrivateActivationGate();
    prepareGate();
    openSettings(self);
    ytk_log(@"gated open returned from YTKPlus opener");
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
            ytk_openYTKSettingsViaGatedPath(self);
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
                   dispatch_get_main_queue(), ^{ ytk_openYTKSettingsViaGatedPath(self); });
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
    ytk_log(@"boot v3.0-gated-settings-open constructor entered");

    preseedKeychain();
    ytk_log(@"preseed done");

    ytk_installPresentInterceptor();

    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_retrySwizzle(1);
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_log(@"5s heartbeat reached"); });
}

