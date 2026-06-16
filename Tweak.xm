/*
 *  YTKHelper / YTKActivator v2.5-debug — persistent overlay log window
 *
 *  v2.4 used UIAlertController which loses races against YTKPlus's own
 *  modals (and against early-launch UI that isn't ready yet). v2.5 replaces
 *  the popup approach with a dedicated UIWindow at level
 *  UIWindowLevelAlert + 1000 that holds a scrollable UITextView. Nothing
 *  YTKPlus presents can hide it. Every checkpoint appends a line. Tap the
 *  "X" in the corner to dismiss.
 *
 *  Lines you should see, in order:
 *    [boot] preseed done
 *    [boot] swizzle pass: N classes patched
 *    [boot] RootOptionsController loaded: YES/NO
 *    [boot] dyld add-image callback: registered/skipped
 *    [dyld] image #N loaded — ROC=YES/NO  (one line per dyld callback fire)
 *    [dyld] late swizzle landed on M classes
 *    [hit]  -[<Class> openCheckLicense] intercepted
 *    [open] presenting RootOptionsController on <Class>
 *    [err]  ...                              (any failure paths)
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
#pragma mark — Persistent overlay log window
// ============================================================
//
// A UIWindow at UIWindowLevelAlert + 1000 holding a UITextView. Always on
// top, can't be hidden by alerts or modals. Holds a running log buffer so
// lines appended before the window is up still show once it's ready.

static UIWindow      *gLogWindow   = nil;
static UITextView    *gLogTextView = nil;
static NSMutableString *gLogBuffer = nil;  // pre-window buffer
static dispatch_queue_t gLogSerialQ = NULL;

static void ytk_logEnsureQueue(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gLogSerialQ = dispatch_queue_create("me.itzzace.ytkhelper.log", DISPATCH_QUEUE_SERIAL);
        gLogBuffer  = [NSMutableString string];
    });
}

static void ytk_buildOverlayWindow(void) {
    if (gLogWindow) return;

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
            if ([s isKindOfClass:[UIWindowScene class]]) {
                ws = (UIWindowScene *)s;
                break;
            }
        }
    }
    if (!ws) return;

    UIWindow *w = [[UIWindow alloc] initWithWindowScene:ws];
    w.windowLevel = UIWindowLevelAlert + 1000;
    w.backgroundColor = [UIColor clearColor];

    UIViewController *root = [[UIViewController alloc] init];
    root.view.backgroundColor = [UIColor clearColor];
    w.rootViewController = root;

    CGRect bounds = ws.coordinateSpace.bounds;
    CGFloat height = MIN(360.0, bounds.size.height * 0.45);
    CGFloat margin = 12.0;
    CGFloat topInset = 60.0;

    UIView *panel = [[UIView alloc] initWithFrame:
        CGRectMake(margin, topInset,
                   bounds.size.width - margin * 2,
                   height)];
    panel.backgroundColor = [UIColor colorWithRed:0 green:0 blue:0 alpha:0.85];
    panel.layer.cornerRadius = 8;
    panel.layer.borderColor = [UIColor systemGreenColor].CGColor;
    panel.layer.borderWidth = 1.0;
    panel.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleBottomMargin;
    [root.view addSubview:panel];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(10, 4, panel.bounds.size.width - 50, 20)];
    title.text = @"YTKHelper v2.5-debug log";
    title.textColor = [UIColor systemGreenColor];
    title.font = [UIFont boldSystemFontOfSize:12];
    title.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [panel addSubview:title];

    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(panel.bounds.size.width - 38, 0, 36, 28);
    closeBtn.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [closeBtn setTitle:@"✕" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    closeBtn.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    [closeBtn addTarget:[NSBlockOperation class] action:@selector(class) forControlEvents:UIControlEventTouchUpInside];
    [panel addSubview:closeBtn];

    UITextView *tv = [[UITextView alloc] initWithFrame:
        CGRectMake(4, 28, panel.bounds.size.width - 8, panel.bounds.size.height - 32)];
    tv.editable = NO;
    tv.selectable = YES;
    tv.backgroundColor = [UIColor clearColor];
    tv.textColor = [UIColor whiteColor];
    tv.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [panel addSubview:tv];

    // Wire close button to a real action.
    objc_setAssociatedObject(closeBtn, "ytk_panel", panel, OBJC_ASSOCIATION_ASSIGN);
    [closeBtn removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];

    // Use a small helper class registered at runtime to handle the tap
    // without needing a separate ObjC interface.
    static Class handlerClass = nil;
    if (!handlerClass) {
        handlerClass = objc_allocateClassPair([NSObject class], "YTKHelperLogCloseHandler", 0);
        IMP closeImp = imp_implementationWithBlock(^(id self, UIButton *sender) {
            UIView *p = objc_getAssociatedObject(sender, "ytk_panel");
            p.hidden = !p.hidden;
        });
        class_addMethod(handlerClass, @selector(toggle:), closeImp, "v@:@");
        objc_registerClassPair(handlerClass);
    }
    static id handlerInstance = nil;
    if (!handlerInstance) handlerInstance = [[handlerClass alloc] init];
    [closeBtn addTarget:handlerInstance action:@selector(toggle:) forControlEvents:UIControlEventTouchUpInside];

    w.hidden = NO;
    [w makeKeyAndVisible];

    // makeKeyAndVisible can steal first-responder/key-window from YouTube;
    // immediately hand it back.
    for (UIWindow *win in ws.windows) {
        if (win != w && [win isKindOfClass:[UIWindow class]]) {
            [win makeKeyWindow];
            break;
        }
    }

    gLogWindow   = w;
    gLogTextView = tv;

    // Flush buffered lines.
    if (gLogBuffer.length > 0) {
        tv.text = [gLogBuffer copy];
        // Scroll to bottom.
        NSRange end = NSMakeRange(tv.text.length, 0);
        [tv scrollRangeToVisible:end];
    }
}

static void ytk_logAppendOnMain(NSString *line) {
    if (!gLogTextView) {
        ytk_buildOverlayWindow();
    }
    if (gLogTextView) {
        NSString *current = gLogTextView.text ?: @"";
        gLogTextView.text = [current stringByAppendingString:line];
        NSRange end = NSMakeRange(gLogTextView.text.length, 0);
        [gLogTextView scrollRangeToVisible:end];
    }
}

static void ytk_log(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
                      [df stringFromDate:[NSDate date]], msg];

    LOG(@"%@", msg);
    ytk_logEnsureQueue();
    dispatch_async(gLogSerialQ, ^{
        [gLogBuffer appendString:line];
    });
    NSString *forUI = line;
    dispatch_async(dispatch_get_main_queue(), ^{
        ytk_logAppendOnMain(forUI);
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
}

// ============================================================
#pragma mark — RootOptionsController opener
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
    for (UIWindow *w in ws.windows) {
        if (w == gLogWindow) continue;
        if (w.isKeyWindow) { top = w.rootViewController; break; }
    }
    if (!top) {
        for (UIWindow *w in ws.windows) {
            if (w == gLogWindow) continue;
            top = w.rootViewController; break;
        }
    }
    while (top.presentedViewController) top = top.presentedViewController;
    return top;
}

static void ytk_presentRootOptions(id self) {
    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) {
        ytk_log(@"[err] RootOptionsController class is NIL — YTKPlus.dylib didn't load");
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
        ytk_log(@"[open] presenting RootOptionsController on %@", NSStringFromClass([host class]));
        [host presentViewController:nav animated:YES completion:nil];
    } else {
        ytk_log(@"[err] no host VC available to present from");
    }
}

// ============================================================
#pragma mark — openCheckLicense swizzle
// ============================================================

static SEL kOpenCheckLicenseSel = NULL;

static void ytk_openCheckLicense_replacement(id self, SEL _cmd) {
    NSString *cls = NSStringFromClass([self class]);
    ytk_log(@"[hit] -[%@ openCheckLicense] intercepted", cls);
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
                method_setImplementation(methods[j],
                    (IMP)ytk_openCheckLicense_replacement);
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

// ============================================================
#pragma mark — dyld late-swizzle fallback
// ============================================================
static volatile int kSwizzleSucceeded = 0;
static volatile int kDyldImageCount   = 0;

static void ytk_addImageCallback(const struct mach_header *mh, intptr_t slide) {
    int n = ++kDyldImageCount;
    if (kSwizzleSucceeded) return;

    Class roc = NSClassFromString(@"RootOptionsController");
    if (!roc) {
        if (n <= 5 || n % 25 == 0) {
            ytk_log(@"[dyld] image #%d loaded — ROC=NO (still waiting)", n);
        }
        return;
    }

    NSMutableArray *names = [NSMutableArray array];
    int swizzled = ytk_runSwizzlePass(names);

    if (swizzled > 0) {
        kSwizzleSucceeded = 1;
        ytk_log(@"[dyld] image #%d — ROC=YES — late swizzle landed on %d class(es): %@",
                n, swizzled, [names componentsJoinedByString:@", "]);
    } else {
        ytk_log(@"[dyld] image #%d — ROC=YES but 0 classes had openCheckLicense", n);
    }
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    ytk_logEnsureQueue();
    ytk_log(@"[boot] YTKHelper v2.5-debug loaded");

    preseedKeychain();
    ytk_log(@"[boot] preseed done");

    NSMutableArray *names = [NSMutableArray array];
    int swizzledNow = ytk_runSwizzlePass(names);
    BOOL rocLoaded  = (NSClassFromString(@"RootOptionsController") != nil);

    ytk_log(@"[boot] swizzle pass: %d class(es)%@%@",
            swizzledNow,
            swizzledNow > 0 ? @" → " : @"",
            swizzledNow > 0 ? [names componentsJoinedByString:@", "] : @"");
    ytk_log(@"[boot] RootOptionsController loaded: %@", rocLoaded ? @"YES" : @"NO");

    if (rocLoaded && swizzledNow > 0) {
        kSwizzleSucceeded = 1;
        ytk_log(@"[boot] dyld add-image callback: skipped (already done)");
    } else {
        _dyld_register_func_for_add_image(ytk_addImageCallback);
        ytk_log(@"[boot] dyld add-image callback: REGISTERED (waiting for late YTKPlus load)");
    }

    // Force the overlay window up after UI is plausibly ready, even if no
    // log line happens to fire in that window. This is what makes the log
    // visible at all on early-launch glitched devices.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        ytk_buildOverlayWindow();
        ytk_log(@"[boot] overlay window mounted — tap ✕ to hide");
    });
}
