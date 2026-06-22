/*
 *  ytkcore v6.6-ytkplus-5.7.1
 *
 *  Preserves the integrity seal during launch and seeds the YTKPlus 5.7.1
 *  version gate. YTKPlus 5.7.1 rejects 5.7 after the server-side update.
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/mman.h>
#import <unistd.h>
#import <libkern/OSCacheControl.h>
#if __has_include(<ptrauth.h>)
#import <ptrauth.h>
#endif

#define LOG(fmt, ...) NSLog(@"[ytkcore] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kFakeEmail   = @"activated@itzzace.dev";
static NSString *const kFakeDevice  = @"ytkcore";
static NSString *const kFakeToken   = @"core-session-token";
static NSString *const kYTKVersion  = @"5.7.1";
static NSString *const kJunkSeal    = @"INVALID-SEAL-FORCE-VERIFY-FAIL";
static NSString *const kFutureTs    = @"9999999999.000";
static NSInteger const kYTKDirectSettingsOverlayTag = 0x59544b31;
static NSString *const kYTKCoreBuildVersion = @"6.6";

static const uintptr_t kYTKRootOptionsGatePrepOffset    = 0x000b91e0;
static const uintptr_t kYTKFinalSettingsPresenterOffset = 0x000b9120;
static const uintptr_t kYTKActivationGuardOffset        = 0x000b7758;
static const uintptr_t kYTKReadKeychainOffset           = 0x000b7a5c;
static const uintptr_t kYTKHMACOffset                   = 0x000b7f04;
static const uintptr_t kYTKExpectedGateValueOffset      = 0x000b7e80;
static const uintptr_t kYTKSecretOffset                 = 0x000b8280;
static const uintptr_t kYTKPrivateGateAccountOffset     = 0x000b7cd4;
static const uintptr_t kYTKCleanScanOffset              = 0x000b8690;
static const uintptr_t kYTKWriteKeychainOffset          = 0x000ba628;
static const uintptr_t kYTKRootOptionsValidationOffset  = 0x000f1f0c;
static const uintptr_t kYTKMasterFeatureFlagPatchOffset = 0x00039808;
static const uintptr_t kYTKDownloadFeatureGateOffset    = 0x0000683c;
static const uintptr_t kYTKAdsFeatureGateOffset         = 0x0000c2f4;

static NSString *ytk_logPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"ytkcore-debug.log"];
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

static void ytk_seedPrivateActivationGate(void);
static void *ytk_findYTKPlusAddress(uintptr_t offset);
static void ytk_patchStartupFeatureGates(NSString *reason);

static void preseedKeychain(void) {
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    writeKeychainValue(@"auth_email_secure",    kFakeEmail);
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   kFakeDevice);
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   kFakeToken);
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
}

static void preseedLaunchActivationState(NSString *reason) {
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    writeKeychainValue(@"auth_email_secure",    kFakeEmail);
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   kFakeDevice);
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   kFakeToken);
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
    ytk_log(@"launch keychain state reseeded without private calls: %@", reason);
}

static NSArray<NSString *> *ytk_v61AccidentalFeatureDefaultKeys(void) {
    return @[
        @"kEnableDownloadit",
        @"kEnablePlayInBackgrounds",
        @"kEnableHoldToSeek",
        @"kEnableisSpeed",
        @"kEnableYTKPiP",
        @"kEnableYTKLoop",
        @"kEnableNoAds",
        @"kEnablefixvideoplayback",
        @"kEnableShowProgressBar",
        @"kEnableShowMediaController",
        @"kEnableCustomDoubleTapToSkipDuration",
        @"kEnablePlayHDVideosOverCellur",
        @"kEnableNoPremiumpopup",
        @"kEnableNoYTUpdate",
        @"kEnableNoExpirityDownloaded"
    ];
}

static void cleanupV61FeatureDefaultsIfNeeded(void) {
    NSString *creditKey = @"com.itzzace.ytkelevator.creditPopupVersion";
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if (![[defaults stringForKey:creditKey] isEqualToString:@"6.1"]) return;
    int removed = 0;
    for (NSString *key in ytk_v61AccidentalFeatureDefaultKeys()) {
        if ([defaults objectForKey:key] != nil) {
            [defaults removeObjectForKey:key];
            removed++;
        }
    }
    [defaults synchronize];
    ytk_log(@"removed v6.1 accidental feature defaults count=%d", removed);
}

static NSString *ytk_describePrefValue(id value) {
    if (!value || value == (id)kCFNull) return @"nil";
    if ([value isKindOfClass:[NSNumber class]]) {
        return [NSString stringWithFormat:@"%@/%@", [value boolValue] ? @"YES" : @"NO", value];
    }
    if ([value isKindOfClass:[NSString class]]) return value;
    return [NSString stringWithFormat:@"%@:%@", NSStringFromClass([value class]), value];
}

static void ytk_logFeaturePrefs(NSString *reason) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *ytkPlus = [defaults dictionaryForKey:@"YTKPlus"];
    NSArray<NSString *> *plainKeys = @[
        @"kEnableOldDarkTheme",
        @"kEnableDownloadit",
        @"kEnableYTKPiP",
        @"kEnableisSpeed",
        @"kEnablePlayInBackgrounds",
        @"kEnableYTKLoop",
        @"kEnableNoAds",
        @"kEnableShowMediaController",
        @"vlcGesturesDisabled",
        @"videoAutoPlayEnabled"
    ];
    NSArray<NSString *> *nestedKeys = @[
        @"kEnableHoldToSeek",
        @"kSeekDuration",
        @"kVolumeSide",
        @"kBrightnessSide",
        @"sponsorBlock",
        @"autoSkipShorts"
    ];

    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (NSString *key in plainKeys) {
        [parts addObject:[NSString stringWithFormat:@"%@=%@",
                          key,
                          ytk_describePrefValue([defaults objectForKey:key])]];
    }
    ytk_log(@"feature prefs plain reason=%@ %@", reason ?: @"nil", [parts componentsJoinedByString:@" "]);

    [parts removeAllObjects];
    for (NSString *key in nestedKeys) {
        [parts addObject:[NSString stringWithFormat:@"YTKPlus.%@=%@",
                          key,
                          ytk_describePrefValue(ytkPlus[key])]];
    }
    ytk_log(@"feature prefs nested reason=%@ dict=%@ %@",
            reason ?: @"nil",
            ytkPlus ? @"present" : @"nil",
            [parts componentsJoinedByString:@" "]);
}

static void ytk_logOverlayDiagnostics(NSString *reason) {
    NSArray<NSString *> *classNames = @[
        @"YTMainAppControlsOverlayView",
        @"YTMainAppVideoPlayerOverlayViewController",
        @"YTMainAppVideoPlayerOverlayView",
        @"YTInlinePlayerBarContainerView"
    ];
    for (NSString *className in classNames) {
        Class cls = NSClassFromString(className);
        ytk_log(@"overlay diag reason=%@ class=%@ exists=%@",
                reason ?: @"nil",
                className,
                cls ? @"YES" : @"NO");
        if (!cls) continue;

        NSArray<NSString *> *selectors = @[
            @"initWithDelegate:",
            @"setOverlayVisible:",
            @"topControlsAccessibilityContainerView",
            @"ytkControls",
            @"setYtkControls:",
            @"handleYTKDownloadButton:",
            @"handleYTKPiPButton:",
            @"iosPlayerWithPlayer",
            @"setupVolumeAndBrightnessGestures",
            @"handleVolumeGesture:",
            @"handleBrightnessGesture:"
        ];
        NSMutableArray<NSString *> *parts = [NSMutableArray array];
        for (NSString *selectorName in selectors) {
            SEL sel = sel_registerName(selectorName.UTF8String);
            BOOL instanceHas = class_getInstanceMethod(cls, sel) != NULL;
            BOOL responds = class_getMethodImplementation(cls, sel) != _objc_msgForward;
            [parts addObject:[NSString stringWithFormat:@"%@=%@/%@",
                              selectorName,
                              instanceHas ? @"M" : @"-",
                              responds ? @"I" : @"-"]];
        }
        ytk_log(@"overlay diag methods class=%@ %@", className, [parts componentsJoinedByString:@" "]);
    }
}

static void scheduleLaunchReseeds(void) {
    NSArray<NSNumber *> *delays = @[ @0.25, @1.0, @3.0, @8.0 ];
    for (NSNumber *delay in delays) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay.doubleValue * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            preseedLaunchActivationState([NSString stringWithFormat:@"launch +%.2fs", delay.doubleValue]);
            if (ytk_findYTKPlusAddress(kYTKPrivateGateAccountOffset)) {
                ytk_seedPrivateActivationGate();
                ytk_patchStartupFeatureGates([NSString stringWithFormat:@"launch +%.2fs", delay.doubleValue]);
            }
            ytk_logFeaturePrefs([NSString stringWithFormat:@"launch +%.2fs", delay.doubleValue]);
            ytk_logOverlayDiagnostics([NSString stringWithFormat:@"launch +%.2fs", delay.doubleValue]);
        });
    }

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(__unused NSNotification *note) {
        preseedLaunchActivationState(@"app became active");
        if (ytk_findYTKPlusAddress(kYTKPrivateGateAccountOffset)) {
            ytk_seedPrivateActivationGate();
            ytk_patchStartupFeatureGates(@"app became active");
        }
        ytk_logFeaturePrefs(@"app became active");
        ytk_logOverlayDiagnostics(@"app became active");
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

static void ytk_callVoidFunction(uintptr_t offset, NSString *name) {
    void *ptr = ytk_findYTKPlusAddress(offset);
    if (!ptr) {
        ytk_log(@"private %@ missing at offset 0x%lx", name, (unsigned long)offset);
        return;
    }
    typedef void (*YTKVoidFn)(void);
    YTKVoidFn fn = (YTKVoidFn)ytk_authFunctionPointer(ptr);
    fn();
}

static BOOL ytk_callBoolFunction(uintptr_t offset, NSString *name) {
    void *ptr = ytk_findYTKPlusAddress(offset);
    if (!ptr) {
        ytk_log(@"private %@ missing at offset 0x%lx", name, (unsigned long)offset);
        return NO;
    }
    typedef int (*YTKBoolFn)(void);
    YTKBoolFn fn = (YTKBoolFn)ytk_authFunctionPointer(ptr);
    return fn() != 0;
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
    NSString *shortHash = ytk_callStringFunction(kYTKExpectedGateValueOffset, @"expectedGate");
    NSString *existing = account ? readKeychainValue(account) : nil;
    NSString *ytkExisting = account ? ytk_callYTKRead(account) : nil;
    NSString *device = readKeychainValue(@"auth_device_secure") ?: ytk_callYTKRead(@"auth_device_secure") ?: kFakeDevice;

    NSString *sealInputV1 = (shortHash.length && device.length) ? [shortHash stringByAppendingString:device] : nil;
    NSString *manualIntegritySealV1 = sealInputV1 ? ytk_callHMAC(sealInputV1, secret) : nil;
    NSString *manualSealInput = (shortHash.length && device.length) ?
        [NSString stringWithFormat:@"%@%@%@", shortHash, device, readKeychainValue(@"auth_session_token") ?: kFakeToken] : nil;
    NSString *manualIntegritySeal = manualSealInput ? ytk_callHMAC(manualSealInput, secret) : nil;
    NSString *officialIntegritySeal = readKeychainValue(@"auth_integrity_seal") ?: ytk_callYTKRead(@"auth_integrity_seal");

    ytk_log(@"gate diag account=%@ existing=%@ ytkExisting=%@ device=%@ shortHash=%@ currentSeal=%@ sealV1=%@ sealV2=%@ clean=%@",
            account ?: @"nil",
            existing ?: @"nil",
            ytkExisting ?: @"nil",
            device ?: @"nil",
            shortHash ?: @"nil",
            officialIntegritySeal ?: @"nil",
            manualIntegritySealV1 ?: @"nil",
            manualIntegritySeal ?: @"nil",
            clean ?: @"nil");

    if (account.length && shortHash.length) {
        writeKeychainValue(@"auth_device_secure", device);
        writeKeychainValue(account, shortHash);
        ytk_callYTKWrite(account, shortHash);
        if (manualIntegritySeal.length) {
            writeKeychainValue(@"auth_integrity_seal", manualIntegritySeal);
            ytk_callYTKWrite(@"auth_integrity_seal", manualIntegritySeal);
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

static _Thread_local int gPresentDepth = 0;
static void (*orig_presentViewController)(id, SEL, UIViewController *, BOOL, void (^)(void)) = NULL;
static BOOL gActivationGuardPatched = NO;
static BOOL gRootOptionsValidationPatched = NO;
static BOOL gMasterFeatureFlagPatched = NO;
static BOOL gDownloadFeatureGatePatched = NO;
static BOOL gAdsFeatureGatePatched = NO;

static BOOL ytk_patchYTKInstruction(uintptr_t offset,
                                    uint32_t replacement,
                                    NSString *label,
                                    BOOL *patchedFlag) {
    if (*patchedFlag) return YES;

    void *ptr = ytk_findYTKPlusAddress(offset);
    if (!ptr) {
        ytk_log(@"%@ patch failed: instruction missing offset=0x%lx", label, (unsigned long)offset);
        return NO;
    }

    uint32_t *code = (uint32_t *)ptr;
    uint32_t original = code[0];
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 0x4000;
    uintptr_t page = (uintptr_t)ptr & ~((uintptr_t)pageSize - 1);

    if (mprotect((void *)page, (size_t)pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        ytk_log(@"%@ patch failed: mprotect errno=%d ptr=%p", label, errno, ptr);
        return NO;
    }

    code[0] = replacement;
    sys_icache_invalidate(ptr, 4);
    mprotect((void *)page, (size_t)pageSize, PROT_READ | PROT_EXEC);

    *patchedFlag = YES;
    ytk_log(@"%@ patched ptr=%p original=%08x replacement=%08x", label, ptr, original, replacement);
    return YES;
}

static BOOL ytk_patchYTKFunctionReturnYES(uintptr_t offset, NSString *label, BOOL *patchedFlag) {
    if (*patchedFlag) return YES;

    void *ptr = ytk_findYTKPlusAddress(offset);
    if (!ptr) {
        ytk_log(@"%@ patch failed: function missing offset=0x%lx", label, (unsigned long)offset);
        return NO;
    }

    uint32_t *code = (uint32_t *)ptr;
    uint32_t original0 = code[0];
    uint32_t original1 = code[1];
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 0x4000;
    uintptr_t page = (uintptr_t)ptr & ~((uintptr_t)pageSize - 1);

    if (mprotect((void *)page, (size_t)pageSize, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        ytk_log(@"%@ patch failed: mprotect errno=%d ptr=%p", label, errno, ptr);
        return NO;
    }

    code[0] = 0x52800020; // mov w0, #1
    code[1] = 0xd65f03c0; // ret
    sys_icache_invalidate(ptr, 8);
    mprotect((void *)page, (size_t)pageSize, PROT_READ | PROT_EXEC);

    *patchedFlag = YES;
    ytk_log(@"%@ patched ptr=%p original=%08x %08x", label, ptr, original0, original1);
    return YES;
}

static BOOL ytk_patchActivationGuardReturnYES(void) {
    return ytk_patchYTKFunctionReturnYES(kYTKActivationGuardOffset,
                                         @"activation guard",
                                         &gActivationGuardPatched);
}

static BOOL ytk_patchRootOptionsValidationReturnYES(void) {
    return ytk_patchYTKFunctionReturnYES(kYTKRootOptionsValidationOffset,
                                         @"root options validation",
                                         &gRootOptionsValidationPatched);
}

static BOOL ytk_patchDownloadFeatureGateReturnYES(void) {
    return ytk_patchYTKFunctionReturnYES(kYTKDownloadFeatureGateOffset,
                                         @"download feature gate",
                                         &gDownloadFeatureGatePatched);
}

static BOOL ytk_patchAdsFeatureGateReturnYES(void) {
    return ytk_patchYTKFunctionReturnYES(kYTKAdsFeatureGateOffset,
                                         @"ads feature gate",
                                         &gAdsFeatureGatePatched);
}

static BOOL ytk_patchMasterFeatureFlagReturnActive(void) {
    return ytk_patchYTKInstruction(kYTKMasterFeatureFlagPatchOffset,
                                   0x5280003b, // mov w27, #1
                                   @"master feature flag",
                                   &gMasterFeatureFlagPatched);
}

static void ytk_patchStartupFeatureGates(NSString *reason) {
    BOOL master = ytk_patchMasterFeatureFlagReturnActive();
    BOOL activation = ytk_patchActivationGuardReturnYES();
    BOOL root = ytk_patchRootOptionsValidationReturnYES();
    BOOL download = ytk_patchDownloadFeatureGateReturnYES();
    BOOL ads = ytk_patchAdsFeatureGateReturnYES();
    ytk_log(@"startup feature gates patched reason=%@ master=%@ activation=%@ root=%@ download=%@ ads=%@",
            reason ?: @"nil",
            master ? @"YES" : @"NO",
            activation ? @"YES" : @"NO",
            root ? @"YES" : @"NO",
            download ? @"YES" : @"NO",
            ads ? @"YES" : @"NO");
}

static BOOL ytk_presentRootOptionsFallback(UIViewController *host) {
    ytk_logFeaturePrefs(@"before root fallback present");
    Class rootClass = NSClassFromString(@"RootOptionsController");
    if (!rootClass) {
        ytk_log(@"fallback present failed: RootOptionsController missing");
        return NO;
    }

    id root = [[rootClass alloc] initWithStyle:UITableViewStyleGrouped];
    if (!root) {
        ytk_log(@"fallback present failed: RootOptionsController init returned nil");
        return NO;
    }

    SEL gateSetter = sel_registerName("set_ytkGateVerified:");
    if ([root respondsToSelector:gateSetter]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(root, gateSetter, YES);
        ytk_log(@"fallback set RootOptionsController _ytkGateVerified=YES");
    } else {
        ytk_log(@"fallback RootOptionsController missing set_ytkGateVerified:");
    }

    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:root];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    ytk_log(@"fallback presenting RootOptionsController host=%@ root=%@",
            NSStringFromClass([host class]), NSStringFromClass([root class]));

    gPresentDepth++;
    if (orig_presentViewController) {
        orig_presentViewController(host,
                                   @selector(presentViewController:animated:completion:),
                                   nav,
                                   YES,
                                   ^{
            ytk_log(@"fallback present completion top=%@",
                    ytk_topVC() ? NSStringFromClass([ytk_topVC() class]) : @"nil");
        });
    } else {
        [host presentViewController:nav animated:YES completion:^{
            ytk_log(@"fallback present completion top=%@",
                    ytk_topVC() ? NSStringFromClass([ytk_topVC() class]) : @"nil");
        }];
    }
    gPresentDepth--;
    return YES;
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

    ytk_seedPrivateActivationGate();
    ytk_logFeaturePrefs(@"before gated settings open");
    ytk_patchActivationGuardReturnYES();
    ytk_callVoidFunction(kYTKRootOptionsGatePrepOffset, @"rootOptionsGatePrep");
    BOOL guardBefore = ytk_callBoolFunction(kYTKActivationGuardOffset, @"activationGuard");
    ytk_log(@"gated open activationGuard=%@ email=%@ token=%@",
            guardBefore ? @"YES" : @"NO",
            readKeychainValue(@"auth_email_secure") ?: @"nil",
            readKeychainValue(@"auth_session_token") ?: @"nil");
    void *presentPtr = ytk_findYTKPlusAddress(kYTKFinalSettingsPresenterOffset);
    if (!presentPtr) {
        ytk_log(@"gated open failed: final presenter missing");
        ytk_presentRootOptionsFallback((UIViewController *)self);
        return;
    }

    typedef void (*YTKFinalSettingsPresenterFn)(void *);
    YTKFinalSettingsPresenterFn presentSettings = (YTKFinalSettingsPresenterFn)ytk_authFunctionPointer(presentPtr);

    struct {
        uint8_t padding[0x20];
        __unsafe_unretained id host;
    } context = { {0}, self };

    ytk_log(@"gated open calling YTKPlus final presenter=%p host=%@ gatePrep=0x%lx",
            presentPtr, NSStringFromClass([self class]), (unsigned long)kYTKRootOptionsGatePrepOffset);
    gPresentDepth++;
    presentSettings(&context);
    gPresentDepth--;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *hostVC = [self isKindOfClass:[UIViewController class]] ? (UIViewController *)self : nil;
        UIViewController *presented = hostVC.presentedViewController;
        UIViewController *top = ytk_topVC();
        NSString *topName = top ? NSStringFromClass([top class]) : @"nil";
        NSString *presentedName = presented ? NSStringFromClass([presented class]) : @"nil";
        BOOL presentedSettings = [presentedName containsString:@"UINavigationController"] ||
                                 [presentedName containsString:@"RootOptionsController"] ||
                                 [topName containsString:@"RootOptionsController"];
        ytk_log(@"gated open returned from YTKPlus final presenter top=%@ hostPresented=%@ presented=%@",
                topName, presentedName, presentedSettings ? @"YES" : @"NO");
        if (!presentedSettings && guardBefore && [self isKindOfClass:[UIViewController class]]) {
            ytk_callVoidFunction(kYTKRootOptionsGatePrepOffset, @"rootOptionsGatePrepFallback");
            BOOL guardAfter = ytk_callBoolFunction(kYTKActivationGuardOffset, @"activationGuardFallback");
            ytk_log(@"gated open fallback path guard=%@", guardAfter ? @"YES" : @"NO");
            if (guardAfter) ytk_presentRootOptionsFallback((UIViewController *)self);
        } else if (!presentedSettings) {
            ytk_log(@"gated open fallback skipped: activation guard is not passing");
        }
    });
}

static void ytk_openYTKSettingsViaRootFallback(id self) {
    if (![self isKindOfClass:[UIViewController class]]) {
        UIViewController *top = ytk_topVC();
        ytk_log(@"root fallback host remapped %@ -> %@",
                NSStringFromClass([self class]),
                top ? NSStringFromClass([top class]) : @"nil");
        self = top;
    }
    if (!self) {
        ytk_log(@"root fallback failed: no host");
        return;
    }

    ytk_seedPrivateActivationGate();
    ytk_logFeaturePrefs(@"before root settings open");
    ytk_patchActivationGuardReturnYES();
    ytk_patchRootOptionsValidationReturnYES();
    ytk_callVoidFunction(kYTKRootOptionsGatePrepOffset, @"rootOptionsGatePrepFallback");
    BOOL guardBefore = ytk_callBoolFunction(kYTKActivationGuardOffset, @"activationGuardFallback");
    BOOL rootValidation = ytk_callBoolFunction(kYTKRootOptionsValidationOffset, @"rootOptionsValidationFallback");
    ytk_log(@"root fallback opening guard=%@ rootValidation=%@ email=%@ token=%@ host=%@",
            guardBefore ? @"YES" : @"NO",
            rootValidation ? @"YES" : @"NO",
            readKeychainValue(@"auth_email_secure") ?: @"nil",
            readKeychainValue(@"auth_session_token") ?: @"nil",
            NSStringFromClass([self class]));
    ytk_presentRootOptionsFallback((UIViewController *)self);
}

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
    NSString *key = @"com.itzzace.ytkelevator.creditPopupVersion";
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    if ([[defaults stringForKey:key] isEqualToString:kYTKCoreBuildVersion]) return;
    [defaults setObject:kYTKCoreBuildVersion forKey:key];
    [defaults synchronize];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *host = ytk_topVC();
        if (!host) {
            ytk_log(@"credit popup skipped: no host");
            return;
        }
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"ytkcore"
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
                   dispatch_get_main_queue(), ^{ ytk_openYTKSettingsViaRootFallback(self); });
}

static void ytk_prepareSettingsButtonTouch(id self, SEL _cmd, id sender) {
    ytk_log(@"settings gear touch-down on %@", NSStringFromClass([self class]));
    ytk_seedPrivateActivationGate();
    ytk_patchActivationGuardReturnYES();
    ytk_patchRootOptionsValidationReturnYES();
    ytk_callVoidFunction(kYTKRootOptionsGatePrepOffset, @"rootOptionsGatePrepTouchDown");
    BOOL guard = ytk_callBoolFunction(kYTKActivationGuardOffset, @"activationGuardTouchDown");
    BOOL rootValidation = ytk_callBoolFunction(kYTKRootOptionsValidationOffset, @"rootOptionsValidationTouchDown");
    ytk_log(@"settings gear prepared guard=%@ rootValidation=%@",
            guard ? @"YES" : @"NO",
            rootValidation ? @"YES" : @"NO");
}

static void ytk_firstSettingsButtonTapped(id self, SEL _cmd, id sender) {
    ytk_log(@"first settings gear tapped on %@", NSStringFromClass([self class]));
    ytk_logFeaturePrefs(@"first settings gear tapped");
    ytk_openYTKSettingsViaRootFallback(self);
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

static char kYTKCoreCapturedFirstGearKey;
static char kYTKCoreAutoForwardedGearKey;
static void (*orig_addSubview)(id, SEL, UIView *) = NULL;

static UIViewController *ytk_hostControllerForView(UIView *view) {
    UIResponder *responder = view;
    while (responder) {
        responder = responder.nextResponder;
        if ([responder isKindOfClass:[UIViewController class]]) {
            return (UIViewController *)responder;
        }
    }
    return nil;
}

static BOOL ytk_isDownloadsControllerHost(id host) {
    NSString *className = NSStringFromClass([host class]);
    return [className isEqualToString:@"DownloadsController"] ||
           [className isEqualToString:@"DownloadsController2"] ||
           [className isEqualToString:@"DownloadsVideoController"] ||
           [className isEqualToString:@"DownloadsAudioController"] ||
           [className isEqualToString:@"DownloadsShortController"];
}

static void ytk_attachDirectTargetToFirstGear(UIView *container, UIView *subview) {
    if (![subview isKindOfClass:[UIButton class]]) return;
    UIViewController *host = ytk_hostControllerForView(container);
    if (!host || !ytk_isDownloadsControllerHost(host)) return;
    if (objc_getAssociatedObject(host, &kYTKCoreCapturedFirstGearKey)) return;

    Class cls = [host class];
    class_addMethod(cls, @selector(ytk_firstSettingsButtonTapped:), (IMP)ytk_firstSettingsButtonTapped, "v@:@");
    class_addMethod(cls, @selector(ytk_prepareSettingsButtonTouch:), (IMP)ytk_prepareSettingsButtonTouch, "v@:@");
    class_addMethod(cls, @selector(ytk_firstSettingsButtonLongPressed:), (IMP)ytk_firstSettingsButtonLongPressed, "v@:@");

    NSString *className = NSStringFromClass([host class]);
    UIButton *button = (UIButton *)subview;
    objc_setAssociatedObject(host, &kYTKCoreCapturedFirstGearKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    ytk_log(@"captured first YTKPlus gear button on %@", NSStringFromClass([host class]));

    if ([className isEqualToString:@"DownloadsController2"]) {
        [button addTarget:host action:@selector(ytk_prepareSettingsButtonTouch:) forControlEvents:UIControlEventTouchDown];
        [button addTarget:host action:@selector(ytk_firstSettingsButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
        ytk_log(@"intermediate YTKPlus gear uses direct root fallback tap path");
    } else {
        [button addTarget:host action:@selector(ytk_firstSettingsButtonTapped:) forControlEvents:UIControlEventTouchUpInside];
    }

    if ([className isEqualToString:@"DownloadsController2"] &&
        !objc_getAssociatedObject(host, &kYTKCoreAutoForwardedGearKey)) {
        objc_setAssociatedObject(host, &kYTKCoreAutoForwardedGearKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        ytk_log(@"intermediate YTKPlus gear captured; auto-forward disabled");
    }
}

static void ytk_addSubview_hook(id self, SEL _cmd, UIView *subview) {
    if (orig_addSubview) orig_addSubview(self, _cmd, subview);
    ytk_attachDirectTargetToFirstGear((UIView *)self, subview);
}

static void ytk_installSubviewCapture(void) {
    Method m = class_getInstanceMethod([UIView class], @selector(addSubview:));
    if (!m) {
        ytk_log(@"subview capture failed: addSubview missing");
        return;
    }
    IMP cur = method_getImplementation(m);
    if (cur == (IMP)ytk_addSubview_hook) return;
    orig_addSubview = (void (*)(id, SEL, UIView *))method_setImplementation(m, (IMP)ytk_addSubview_hook);
    ytk_log(@"subview capture installed");
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
    ytk_logFeaturePrefs(@"root options visuals");
    UIViewController *vc = (UIViewController *)self;
    int labels = 0;
    int switches = 0;

    for (UIView *view in ytk_allSubviews(vc.view)) {
        if ([view isKindOfClass:[UILabel class]]) {
            UILabel *label = (UILabel *)view;
            NSString *text = label.text ?: @"";
            NSString *lower = text.lowercaseString;
            if ([lower containsString:@"inactive"] ||
                [lower containsString:@"verify license"] ||
                [lower containsString:@"01-01-2030"] ||
                [lower containsString:@"2030"] ||
                ([lower containsString:@"active"] && [lower containsString:@"license"])) {
                label.text = @"Active (itzzace.)";
                label.textColor = [UIColor systemGreenColor];
                labels++;
            }
        } else if ([view isKindOfClass:[UISwitch class]]) {
            switches++;
        }
    }
    ytk_log(@"root options visuals applied labels=%d switches=%d", labels, switches);
}

static void (*orig_rootViewDidAppear)(id, SEL, BOOL) = NULL;
static void ytk_rootViewDidAppear_hook(id self, SEL _cmd, BOOL animated) {
    if (orig_rootViewDidAppear) orig_rootViewDidAppear(self, _cmd, animated);
    ytk_applyRootOptionsVisuals(self);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_applyRootOptionsVisuals(self); });
}

static void (*orig_rootViewDidLayoutSubviews)(id, SEL) = NULL;
static void ytk_rootViewDidLayoutSubviews_hook(id self, SEL _cmd) {
    if (orig_rootViewDidLayoutSubviews) orig_rootViewDidLayoutSubviews(self, _cmd);
    ytk_applyRootOptionsVisuals(self);
}

static void __attribute__((unused)) ytk_swizzleRootOptionsController(void) {
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
    class_addMethod(cls, @selector(ytk_prepareSettingsButtonTouch:), (IMP)ytk_prepareSettingsButtonTouch, "v@:@");
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
    ytk_log(@"retry %d swizzle any=%@ ROC=%@ rootVisualSwizzle=deferred", attempt, any ? @"YES" : @"NO", roc ? @"YES" : @"NO");
    if (any || attempt >= 30) return;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_retrySwizzle(attempt + 1); });
}

static void ytk_dyldCallback(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    Dl_info info;
    if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;
    if (!strstr(info.dli_fname, "YTKPlus")) return;
    ytk_log(@"YTKPlus image callback path=%s", info.dli_fname);
    preseedLaunchActivationState(@"YTKPlus image callback");
    ytk_seedPrivateActivationGate();
    ytk_patchStartupFeatureGates(@"YTKPlus image callback");
    ytk_logOverlayDiagnostics(@"YTKPlus image callback");
}

__attribute__((constructor))
static void init(void) {
    [[NSFileManager defaultManager] removeItemAtPath:ytk_logPath() error:nil];
    ytk_log(@"boot v6.6-ytkplus-5.7.1 constructor entered");

    preseedKeychain();
    ytk_log(@"preseed done");
    cleanupV61FeatureDefaultsIfNeeded();
    ytk_logFeaturePrefs(@"constructor after cleanup");
    _dyld_register_func_for_add_image(ytk_dyldCallback);
    if (ytk_findYTKPlusAddress(kYTKPrivateGateAccountOffset)) {
        ytk_seedPrivateActivationGate();
    }
    ytk_patchStartupFeatureGates(@"constructor");
    scheduleLaunchReseeds();

    ytk_installPresentInterceptor();
    ytk_installSubviewCapture();
    ytk_showCreditPopupIfNeeded();

    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_retrySwizzle(1);
    });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ ytk_log(@"5s heartbeat reached"); });
}

