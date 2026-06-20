/*
 *  YTKHelper / YTKActivator v2.8-alert-intercept
 *  YTKHelper / YTKActivator v3.8-new-setup-selector
 *
 *  v3.7 updated private offsets for the newer YTKPlus dylib. This build also
 *  handles the new obfuscated DownloadsController settings setup selector.
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
static NSInteger const kYTKDirectSettingsOverlayTag = 0x59544b31;
static NSString *const kYTKHelperBuildVersion = @"3.8";

static const uintptr_t kYTKCompletionOpenSettingsOffset = 0x000b6cc8;
static const uintptr_t kYTKReadKeychainOffset           = 0x000b6b3c;
static const uintptr_t kYTKHMACOffset                   = 0x000b72b8;
static const uintptr_t kYTKSecretOffset                 = 0x000b7634;
static const uintptr_t kYTKPrivateGateAccountOffset     = 0x000b7850;
static const uintptr_t kYTKCleanScanOffset              = 0x000b79fc;
static const uintptr_t kYTKWriteKeychainOffset          = 0x000b8bd4;

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

static void preseedLaunchActivationState(NSString *reason) {
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
    ytk_log(@"launch activation state reseeded: %@", reason);
}

static void scheduleLaunchReseeds(void) {
    NSArray<NSNumber *> *delays = @[ @0.25, @1.0, @3.0, @8.0 ];
    for (NSNumber *delay in delays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            preseedLaunchActivationState([NSString stringWithFormat:@"launch +%.2fs", delay.doubleValue]);
        });
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(__unused NSNotification *note) {
        preseedLaunchActivationState(@"app became active");
    }];
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

static void ytk_callYTKWrite(NSString *account, NSString *value) {
    void *ptr = ytk_findYTKPlusAddress(kYTKWriteKeychainOffset);
    if (!ptr || !account || !value) return;
    typedef void (*YTKWriteFn)(id, id);
    YTKWriteFn fn = (YTKWriteFn)ytk_authFunctionPointer(ptr);
    fn(account, value);
}

static void ytk_seedPrivateActivationGate(void) {
    NSString *account = ytk_callStringFunction(kYTKPrivateGateAccountOffset, @"gateAccount");
    NSString *secret = ytk_callStringFunction(kYTKSecretOffset, @"secret");
    NSString *clean = ytk_callStringFunction(kYTKCleanScanOffset, @"cleanScan");
    NSString *existing = account ? readKeychainValue(account) : nil;
    NSString *ytkExisting = account ? ytk_callYTKRead(account) : nil;
    NSString *device = readKeychainValue(@"auth_device_secure") ?: ytk_callYTKRead(@"auth_device_secure") ?: @"YTKHelper";

    NSString *fullHash = ytk_callHMAC(secret, secret);
    NSString *shortHash = fullHash.length >= 8 ? [fullHash substringToIndex:8] : fullHash;
    NSString *sealInput = (shortHash.length && device.length) ? [shortHash stringByAppendingString:device] : nil;
    NSString *integritySeal = sealInput ? ytk_callHMAC(sealInput, secret) : nil;

    ytk_log(@"gate diag account=%@ existing=%@ ytkExisting=%@ device=%@ shortHash=%@ seal=%@ clean=%@",
            account ?: @"nil",
            existing ?: @"nil",
            ytkExisting ?: @"nil",
            device ?: @"nil",
            shortHash ?: @"nil",
            integritySeal ?: @"nil",
            clean ?: @"nil");

    if (account.length && shortHash.length) {
        writeKeychainValue(@"auth_device_secure", device);
        writeKeychainValue(account, shortHash);
        ytk_callYTKWrite(account, shortHash);
        if (integritySeal.length) {
            writeKeychainValue(@"auth_integrity_seal", integritySeal);
            ytk_callYTKWrite(@"auth_integrity_seal", integritySeal);
        }

        NSString *gateAfter = readKeychainValue(account);
        NSString *ytkGateAfter = ytk_callYTKRead(account);
        NSString *sealAfter = readKeychainValue(@"auth_integrity_seal");
        NSString *ytkSealAfter = ytk_callYTKRead(@"auth_integrity_seal");
        ytk_log(@"gate seeded %@ local=%@ ytk=%@ integrity local=%@ ytk=%@",
                account,
                gateAfter ?: @"nil",
                ytkGateAfter ?: @"nil",
                sealAfter ?: @"nil",
                ytkSealAfter ?: @"nil");
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

    void *openPtr = ytk_findYTKPlusAddress(kYTKCompletionOpenSettingsOffset);
    if (!openPtr) {
        ytk_log(@"gated open failed: completion opener missing");
        return;
    }

    typedef void (*YTKCompletionOpenSettingsFn)(void *, unsigned long);
    YTKCompletionOpenSettingsFn openSettings = (YTKCompletionOpenSettingsFn)ytk_authFunctionPointer(openPtr);

    ytk_log(@"gated open calling completion opener=%p host=%@",
            openPtr, NSStringFromClass([self class]));
    ytk_seedPrivateActivationGate();
    struct {
        uint8_t padding[0x20];
        __unsafe_unretained id host;
    } context = { {0}, self };
    openSettings(&context, 1);
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

static void ytk_showCreditPopupIfNeeded(void) {
    NSString *key = @"com.itzzace.ytkhelper.creditPopupVersion";
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([[defaults stringForKey:key] isEqualToString:kYTKHelperBuildVersion]) return;
    [defaults setObject:kYTKHelperBuildVersion forKey:key];
    [defaults synchronize];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *host = ytk_topVC();
        if (!host) {
            ytk_log(@"credit popup skipped: no host");
            return;
        }
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"YTKHelper"
            message:@"YTKPlus activated by itzzace."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];

        gPresentDepth++;
        if (orig_presentViewController) {
            orig_presentViewController(host,
                                       @selector(presentViewController:animated:completion:),
                                       alert,
                                       YES,
                                       nil);
        } else {
            [host presentViewController:alert animated:YES completion:nil];
        }
        gPresentDepth--;
        ytk_log(@"credit popup shown");
    });
}

static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    ytk_log(@"hit openCheckLicense on %@", NSStringFromClass([self class]));
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_openYTKSettingsViaGatedPath(self); });
}

static void ytk_firstSettingsButtonTapped(id self, SEL _cmd, id sender) {
    ytk_log(@"first settings gear tapped on %@", NSStringFromClass([self class]));
    ytk_openYTKSettingsViaGatedPath(self);
}

static void ytk_firstSettingsButtonLongPressed(id self, SEL _cmd, UILongPressGestureRecognizer *recognizer) {
    if (recognizer.state != UIGestureRecognizerStateBegan) return;

    ytk_log(@"first settings gear long-pressed on %@", NSStringFromClass([self class]));
    SEL feedbackSel = sel_registerName("provideFeedback");
    if ([self respondsToSelector:feedbackSel]) {
        ((void (*)(id, SEL))objc_msgSend)(self, feedbackSel);
    } else {
        UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
        [feedback impactOccurred];
    }

    SEL cleanerSel = sel_registerName("showCleanerOptions");
    if ([self respondsToSelector:cleanerSel]) {
        ((void (*)(id, SEL))objc_msgSend)(self, cleanerSel);
    } else {
        ytk_log(@"long press failed: showCleanerOptions missing");
    }
}

static void ytk_installFirstGearOverlay(id self);

static NSArray<UIView *> *ytk_allSubviews(UIView *root) {
    if (!root) return @[];
    NSMutableArray<UIView *> *views = [NSMutableArray array];
    NSMutableArray<UIView *> *stack = [NSMutableArray arrayWithObject:root];
    while (stack.count) {
        UIView *view = stack.lastObject;
        [stack removeLastObject];
        for (UIView *subview in view.subviews) {
            [views addObject:subview];
            [stack addObject:subview];
        }
    }
    return views;
}

static UIButton *ytk_findFirstSettingsGearButton(UIViewController *vc) {
    UIView *root = vc.view;
    if (!root) return nil;

    NSMutableArray<UIButton *> *buttons = [NSMutableArray array];
    for (UIView *subview in ytk_allSubviews(root)) {
        if (subview.tag == kYTKDirectSettingsOverlayTag) continue;
        if ([subview isKindOfClass:[UIButton class]] && !subview.hidden && subview.alpha > 0.01) {
            UIButton *button = (UIButton *)subview;
            CGRect frameInRoot = [button.superview convertRect:button.frame toView:root];
            CGFloat w = CGRectGetWidth(frameInRoot);
            CGFloat h = CGRectGetHeight(frameInRoot);
            if (w >= 20.0 && w <= 80.0 && h >= 20.0 && h <= 80.0 &&
                CGRectGetMinX(frameInRoot) > CGRectGetMidX(root.bounds) * 0.75) {
                [buttons addObject:button];
            }
        }
    }
    if (!buttons.count) return nil;

    [buttons sortUsingComparator:^NSComparisonResult(UIButton *a, UIButton *b) {
        CGRect af = [a.superview convertRect:a.frame toView:root];
        CGRect bf = [b.superview convertRect:b.frame toView:root];
        CGFloat ay = CGRectGetMidY(af);
        CGFloat by = CGRectGetMidY(bf);
        if (fabs(ay - by) > 8.0) return ay < by ? NSOrderedAscending : NSOrderedDescending;
        CGFloat ax = CGRectGetMinX(af);
        CGFloat bx = CGRectGetMinX(bf);
        return ax < bx ? NSOrderedAscending : (ax > bx ? NSOrderedDescending : NSOrderedSame);
    }];

    CGFloat topY = CGRectGetMidY([buttons.firstObject.superview convertRect:buttons.firstObject.frame toView:root]);
    NSMutableArray<UIButton *> *row = [NSMutableArray array];
    for (UIButton *button in buttons) {
        CGRect frame = [button.superview convertRect:button.frame toView:root];
        if (fabs(CGRectGetMidY(frame) - topY) <= 8.0) [row addObject:button];
    }
    if (!row.count) row = buttons;

    [row sortUsingComparator:^NSComparisonResult(UIButton *a, UIButton *b) {
        CGRect af = [a.superview convertRect:a.frame toView:root];
        CGRect bf = [b.superview convertRect:b.frame toView:root];
        CGFloat ax = CGRectGetMinX(af);
        CGFloat bx = CGRectGetMinX(bf);
        return ax < bx ? NSOrderedAscending : (ax > bx ? NSOrderedDescending : NSOrderedSame);
    }];
    return row.firstObject;
}

static void ytk_refreshFirstGearOverlay(id self) {
    dispatch_async(dispatch_get_main_queue(), ^{ ytk_installFirstGearOverlay(self); });
}

static void ytk_installFirstGearOverlay(id self) {
    if (![self isKindOfClass:[UIViewController class]]) return;
    UIViewController *vc = (UIViewController *)self;
    UIView *root = vc.view;
    if (!root) return;

    UIView *old = [root viewWithTag:kYTKDirectSettingsOverlayTag];
    [old removeFromSuperview];

    UIButton *gear = ytk_findFirstSettingsGearButton(vc);
    if (!gear) {
        ytk_log(@"first gear overlay failed: no candidate on %@", NSStringFromClass([self class]));
        return;
    }

    CGRect frame = [gear.superview convertRect:gear.frame toView:root];
    UIButton *overlay = [UIButton buttonWithType:UIButtonTypeCustom];
    overlay.tag = kYTKDirectSettingsOverlayTag;
    overlay.frame = CGRectInset(frame, -6.0, -6.0);
    overlay.backgroundColor = UIColor.clearColor;
    [overlay addTarget:self action:@selector(ytk_firstSettingsButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(ytk_firstSettingsButtonLongPressed:)];
    longPress.minimumPressDuration = 1.0;
    [overlay addGestureRecognizer:longPress];
    [root addSubview:overlay];
    ytk_log(@"first gear overlay installed frame=%@", NSStringFromCGRect(overlay.frame));
}

static void (*orig_setupSettingsButton)(id, SEL) = NULL;
static void ytk_setupSettingsButton_hook(id self, SEL _cmd) {
    if (orig_setupSettingsButton) orig_setupSettingsButton(self, _cmd);
    ytk_refreshFirstGearOverlay(self);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_installFirstGearOverlay(self); });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_installFirstGearOverlay(self); });
}

static void (*orig_downloadsViewDidLayoutSubviews)(id, SEL) = NULL;
static void ytk_downloadsViewDidLayoutSubviews_hook(id self, SEL _cmd) {
    if (orig_downloadsViewDidLayoutSubviews) orig_downloadsViewDidLayoutSubviews(self, _cmd);
    ytk_installFirstGearOverlay(self);
}

static void ytk_applyRootOptionsVisuals(id self) {
    if (![self isKindOfClass:[UIViewController class]]) return;
    UIViewController *vc = (UIViewController *)self;
    int labels = 0;
    int switches = 0;

    for (UIView *view in ytk_allSubviews(vc.view)) {
        if ([view isKindOfClass:[UILabel class]]) {
            UILabel *label = (UILabel *)view;
            NSString *text = label.text ?: @"";
            NSString *lower = text.lowercaseString;
            if ([lower containsString:@"inactive"] || [lower containsString:@"verify license"]) {
                label.text = @"Active (itzzace.)";
                label.textColor = [UIColor systemGreenColor];
                labels++;
            }
        } else if ([view isKindOfClass:[UISwitch class]]) {
            UISwitch *sw = (UISwitch *)view;
            if (!sw.isOn) [sw setOn:YES animated:NO];
            switches++;
        }
    }
    ytk_log(@"root options visuals applied labels=%d switches=%d", labels, switches);
}

static void (*orig_rootViewDidAppear)(id, SEL, BOOL) = NULL;
static void ytk_rootViewDidAppear_hook(id self, SEL _cmd, BOOL animated) {
    if (orig_rootViewDidAppear) orig_rootViewDidAppear(self, _cmd, animated);
    ytk_applyRootOptionsVisuals(self);
}

static void (*orig_rootViewDidLayoutSubviews)(id, SEL) = NULL;
static void ytk_rootViewDidLayoutSubviews_hook(id self, SEL _cmd) {
    if (orig_rootViewDidLayoutSubviews) orig_rootViewDidLayoutSubviews(self, _cmd);
    ytk_applyRootOptionsVisuals(self);
}

static void ytk_swizzleRootOptionsController(void) {
    Class cls = NSClassFromString(@"RootOptionsController");
    if (!cls) return;

    SEL appearSel = @selector(viewDidAppear:);
    IMP currentAppear = class_getMethodImplementation(cls, appearSel);
    if (currentAppear != (IMP)ytk_rootViewDidAppear_hook) {
        orig_rootViewDidAppear = (void (*)(id, SEL, BOOL))currentAppear;
        if (!class_addMethod(cls, appearSel, (IMP)ytk_rootViewDidAppear_hook, "v@:B")) {
            Method appear = class_getInstanceMethod(cls, appearSel);
            orig_rootViewDidAppear = (void (*)(id, SEL, BOOL))method_setImplementation(appear, (IMP)ytk_rootViewDidAppear_hook);
        }
        ytk_log(@"swizzled RootOptionsController viewDidAppear");
    }

    SEL layoutSel = @selector(viewDidLayoutSubviews);
    IMP currentLayout = class_getMethodImplementation(cls, layoutSel);
    if (currentLayout != (IMP)ytk_rootViewDidLayoutSubviews_hook) {
        orig_rootViewDidLayoutSubviews = (void (*)(id, SEL))currentLayout;
        if (!class_addMethod(cls, layoutSel, (IMP)ytk_rootViewDidLayoutSubviews_hook, "v@:")) {
            Method layout = class_getInstanceMethod(cls, layoutSel);
            orig_rootViewDidLayoutSubviews = (void (*)(id, SEL))method_setImplementation(layout, (IMP)ytk_rootViewDidLayoutSubviews_hook);
        }
        ytk_log(@"swizzled RootOptionsController viewDidLayoutSubviews");
    }
}

static BOOL ytk_swizzleClassNamed(NSString *className) {
    Class cls = NSClassFromString(className);
    if (!cls) return NO;
    class_addMethod(cls, @selector(ytk_firstSettingsButtonTapped:), (IMP)ytk_firstSettingsButtonTapped, "v@:@");
    class_addMethod(cls, @selector(ytk_firstSettingsButtonLongPressed:), (IMP)ytk_firstSettingsButtonLongPressed, "v@:@");

    Method setupMethod = NULL;
    NSArray<NSString *> *setupSelectorNames = @[ @"setupSettingsButton", @"ayTrknboXotbgare" ];
    for (NSString *setupSelectorName in setupSelectorNames) {
        SEL setupSel = sel_registerName(setupSelectorName.UTF8String);
        setupMethod = class_getInstanceMethod(cls, setupSel);
        if (!setupMethod) continue;
        IMP cur = method_getImplementation(setupMethod);
        if (cur != (IMP)ytk_setupSettingsButton_hook) {
            orig_setupSettingsButton = (void (*)(id, SEL))method_setImplementation(setupMethod, (IMP)ytk_setupSettingsButton_hook);
            ytk_log(@"swizzled %@ %@", className, setupSelectorName);
        }
        break;
    }
    if (setupMethod) {
        SEL layoutSel = @selector(viewDidLayoutSubviews);
        IMP currentLayout = class_getMethodImplementation(cls, layoutSel);
        if (currentLayout != (IMP)ytk_downloadsViewDidLayoutSubviews_hook) {
            orig_downloadsViewDidLayoutSubviews = (void (*)(id, SEL))currentLayout;
            if (!class_addMethod(cls, layoutSel, (IMP)ytk_downloadsViewDidLayoutSubviews_hook, "v@:")) {
                Method layout = class_getInstanceMethod(cls, layoutSel);
                orig_downloadsViewDidLayoutSubviews = (void (*)(id, SEL))method_setImplementation(layout, (IMP)ytk_downloadsViewDidLayoutSubviews_hook);
            }
            ytk_log(@"swizzled %@ viewDidLayoutSubviews", className);
        }
    }

    SEL sel = sel_registerName("openCheckLicense");
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return setupMethod != nil;
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
    if (roc) ytk_swizzleRootOptionsController();
    ytk_log(@"retry %d swizzle any=%@ ROC=%@", attempt, any ? @"YES" : @"NO", roc ? @"YES" : @"NO");
    if (any || attempt >= 30) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_retrySwizzle(attempt + 1); });
}

__attribute__((constructor))
static void init(void) {
    [[NSFileManager defaultManager] removeItemAtPath:ytk_logPath() error:nil];
    ytk_log(@"boot v3.8-new-setup-selector constructor entered");

    preseedKeychain();
    ytk_log(@"preseed done");
    scheduleLaunchReseeds();

    ytk_installPresentInterceptor();
    ytk_showCreditPopupIfNeeded();

    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_retrySwizzle(1);
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_log(@"5s heartbeat reached"); });
}

