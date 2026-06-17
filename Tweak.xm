/*
 *  YTKHelper / YTKActivator v2.6-safe-debug
 *
 *  v2.5's overlay UIWindow could fight YouTube's early scene/key-window
 *  setup and make launch hang. This build removes all debug UI and logs to
 *  NSLog plus files instead. It keeps the v2.3 openCheckLicense swizzle and
 *  v2.1 keychain preseed/banlist cache hardening.
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

static dispatch_queue_t gLogQ;
static NSString *gSandboxLogPath;
static NSString *gMobileLogPath;

static void ytk_logInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gLogQ = dispatch_queue_create("me.itzzace.ytkhelper.debuglog", DISPATCH_QUEUE_SERIAL);
        gSandboxLogPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"YTKHelper-debug.log"];
        gMobileLogPath = @"/var/mobile/Library/Logs/YTKHelper-debug.log";
        [[NSFileManager defaultManager] removeItemAtPath:gSandboxLogPath error:nil];
        [[NSFileManager defaultManager] removeItemAtPath:gMobileLogPath error:nil];
    });
}

static void ytk_log(NSString *fmt, ...) {
    ytk_logInit();
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"%@ %@\n", [df stringFromDate:[NSDate date]], msg];
    LOG(@"%@", msg);

    dispatch_async(gLogQ, ^{
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        for (NSString *path in @[gSandboxLogPath, gMobileLogPath]) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
            if (!fh) {
                [data writeToFile:path atomically:YES];
            } else {
                [fh seekToEndOfFile];
                [fh writeData:data];
                [fh closeFile];
            }
        }
    });
}

static void writeKeychainValue(NSString *account, NSString *value) {
    NSDictionary *delQuery = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    OSStatus delStatus = SecItemDelete((__bridge CFDictionaryRef)delQuery);
    if (!value) {
        ytk_log(@"[keychain] delete %@ status=%d", account, (int)delStatus);
        return;
    }

    NSDictionary *addQuery = @{
        (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:     kService,
        (__bridge id)kSecAttrAccount:     account,
        (__bridge id)kSecValueData:       [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible:  (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        (__bridge id)kSecAttrSynchronizable: @NO,
    };
    OSStatus addStatus = SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
    ytk_log(@"[keychain] write %@ del=%d add=%d", account, (int)delStatus, (int)addStatus);
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
    ytk_log(@"[preseed] done");
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
    if (!top) {
        for (UIWindow *w in ws.windows) { top = w.rootViewController; if (top) break; }
    }
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

static void ytk_presentRootOptions(id self) {
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) {
        ytk_log(@"[open] FAIL: RootOptionsController is nil");
        return;
    }

    id allocated = ((id (*)(id, SEL))objc_msgSend)(roc, sel_registerName("alloc"));
    id vc = ((id (*)(id, SEL, NSInteger))objc_msgSend)(allocated,
                                                       sel_registerName("initWithStyle:"),
                                                       UITableViewStyleGrouped);
    if (!vc) {
        ytk_log(@"[open] FAIL: init RootOptionsController returned nil");
        return;
    }

    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;

    UIViewController *host = [self isKindOfClass:[UIViewController class]] ? (UIViewController *)self : ytk_topVC();
    if (!host) {
        ytk_log(@"[open] FAIL: no host VC");
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_log(@"[open] presenting RootOptionsController from %@", NSStringFromClass([host class]));
        [host presentViewController:nav animated:YES completion:^{
            ytk_log(@"[open] present completion fired");
        }];
    });
}

static SEL kOpenCheckLicenseSel = NULL;

static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    ytk_log(@"[hit] -[%@ openCheckLicense] intercepted", NSStringFromClass([self class]));
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_presentRootOptions(self);
    });
}

static int ytk_runSwizzlePass(NSMutableArray *outClassNames) {
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
                method_setImplementation(methods[j], (IMP)ytk_openCheckLicense_replacement);
                if (outClassNames) [outClassNames addObject:NSStringFromClass(cls)];
                swizzled++;
                break;
            }
        }
        free(methods);
    }
    free(classes);
    return swizzled;
}

static volatile int kSwizzleSucceeded = 0;
static volatile int kDyldImageCount = 0;

static void ytk_addImageCallback(const struct mach_header *mh, intptr_t slide) {
    int n = ++kDyldImageCount;
    if (kSwizzleSucceeded) return;

    NSMutableArray *names = [NSMutableArray array];
    int swizzled = ytk_runSwizzlePass(names);
    BOOL rocLoaded = (NSClassFromString(@"RootOptionsController") != nil);

    if (swizzled > 0) {
        kSwizzleSucceeded = 1;
        ytk_log(@"[dyld] image #%d swizzled=%d classes=%@ ROC=%@", n, swizzled,
                [names componentsJoinedByString:@", "], rocLoaded ? @"YES" : @"NO");
    } else if (n <= 5 || n % 25 == 0) {
        ytk_log(@"[dyld] image #%d swizzled=0 ROC=%@", n, rocLoaded ? @"YES" : @"NO");
    }
}

__attribute__((constructor))
static void init(void) {
    ytk_log(@"[boot] YTKHelper v2.6-safe-debug loaded");
    preseedKeychain();

    NSMutableArray *names = [NSMutableArray array];
    int swizzledNow = ytk_runSwizzlePass(names);
    BOOL rocLoaded = (NSClassFromString(@"RootOptionsController") != nil);
    ytk_log(@"[boot] swizzled=%d classes=%@ ROC=%@", swizzledNow,
            [names componentsJoinedByString:@", "], rocLoaded ? @"YES" : @"NO");

    if (swizzledNow > 0) {
        kSwizzleSucceeded = 1;
        ytk_log(@"[boot] dyld callback skipped");
    } else {
        _dyld_register_func_for_add_image(ytk_addImageCallback);
        ytk_log(@"[boot] dyld callback registered");
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_log(@"[boot] delayed 5s heartbeat: app did not hang in constructor");
    });
}

