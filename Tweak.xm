/*
 *  YTKActivator v13 — SecItem-level bypass
 *
 *  KEY FIX: FUN_00046d48 must return 0 (not 1!) to prevent the server
 *  verification call. Returning 1 CAUSES the server call → "Invalid key" popup.
 *
 *  Strategy:
 *    Phase 1 (our constructor, runs before YTKPlus):
 *      - Hook SecItemCopyMatching → return fake keychain values
 *      - Hook SecItemDelete / SecItemAdd → block for ytkplus service
 *      - Hook UIViewController presentViewController → suppress license alerts
 *      - Register _dyld_register_func_for_add_image callback
 *
 *    Phase 2 (dyld callback, fires when YTKPlus image is loaded):
 *      - Hook FUN_00046d48 at base+0x46d48 → return 0 (prevents server call)
 *      - dispatch_after 0.5s → Phase 3
 *
 *    Phase 3 (delayed, after YTKPlus constructor has run):
 *      - Hook DownloadsController settingsVerifyYkChecker_ → present settings
 *
 *  Why bVar1 = true (premium hooks installed):
 *    - Obfuscated status key reads "1" from our SecItem hook
 *    - auth_integrity_seal returns nil (not found)
 *    - length(nil) == 0 → HMAC check is SKIPPED
 *    - Falls through to bVar1 = true
 *
 *  Why no popup:
 *    - email/license/device/expires all present → enters verify path
 *    - session_token/timestamp present → doesn't short-circuit
 *    - FUN_00046d48 returns 0 → condition FALSE → clearAuth (blocked) → no server call
 */
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <substrate.h>
// ============================================================
#pragma mark — Logging
// ============================================================
#define LOG(fmt, ...) NSLog(@"[YTKBypass] " fmt, ##__VA_ARGS__)
// ============================================================
#pragma mark — Constants
// ============================================================
static NSString *const kService = @"me.ikghd.ytkplus.secure";
static NSString *const kFirstRunKey = @"com.itzzace.ytkactivator.firstRun";
static BOOL ytkPlusFound = NO;
// Known keychain account keys
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
// ============================================================
// DYLD_INTERPOSE — replaces system functions via dyld metadata,
// no code pages modified, passes iOS 26+ code signing monitor
// ============================================================
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
    };

// Look up real implementations on first call (bypasses our own interpose)
static OSStatus (*real_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*real_SecItemDelete)(CFDictionaryRef) = NULL;
static OSStatus (*real_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;

static void resolveRealSecItem(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemCopyMatching");
        real_SecItemDelete       = (OSStatus (*)(CFDictionaryRef))dlsym(RTLD_NEXT, "SecItemDelete");
        real_SecItemAdd          = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemAdd");
        // Fall back to looking in Security.framework directly if RTLD_NEXT fails
        if (!real_SecItemCopyMatching) {
            void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW | RTLD_NOLOAD);
            if (sec) {
                real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(sec, "SecItemCopyMatching");
                real_SecItemDelete       = (OSStatus (*)(CFDictionaryRef))dlsym(sec, "SecItemDelete");
                real_SecItemAdd          = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(sec, "SecItemAdd");
            }
        }
    });
}

// ============================================================
#pragma mark — Phase 1: SecItemCopyMatching hook
// ============================================================
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    @autoreleasepool {
        if (!ytkPlusFound) return real_SecItemCopyMatching(query, result);

        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *service = dict[(__bridge id)kSecAttrService];

        if (![service isEqualToString:kService]) {
            return real_SecItemCopyMatching(query, result);
        }

        NSString *account = dict[(__bridge id)kSecAttrAccount];

        // Keys that must return nil (not found) to skip HMAC checks
        if ([account isEqualToString:kAuthSeal] ||
            [account isEqualToString:kAuthLastSeal]) {
            LOG(@"SecItemCopyMatching: %@ → NOT FOUND (skip HMAC)", account);
            if (result) *result = NULL;
            return errSecItemNotFound;
        }

        // Keys with specific fake values
        NSString *fakeValue = nil;

        if ([account isEqualToString:kAuthEmail]) {
            fakeValue = @"bypass@ytk.local";
        } else if ([account isEqualToString:kAuthLicense]) {
            fakeValue = @"BYPASS-0000-0000-0000";
        } else if ([account isEqualToString:kAuthDevice]) {
            fakeValue = @"FAKEDEVICE-BYPASS-V13";
        } else if ([account isEqualToString:kAuthExpires]) {
            fakeValue = @"01-01-2030 12:00 AM";
        } else if ([account isEqualToString:kAuthSessionToken]) {
            fakeValue = @"FAKETOKEN-BYPASS-V13";
        } else if ([account isEqualToString:kAuthTimestamp]) {
            fakeValue = @"9999999999";
        } else if ([account isEqualToString:kEnabledStatus]) {
            fakeValue = @"1";
        } else if ([account isEqualToString:kActivationLogged]) {
            fakeValue = @"1";
        } else if ([account isEqualToString:kStatsSent]) {
            fakeValue = @"1";
        } else {
            // Any unknown key (including obfuscated status keys) → "1"
            fakeValue = @"1";
        }

        LOG(@"SecItemCopyMatching: %@ → \"%@\"", account ?: @"(nil account)", fakeValue);

        if (result) {
            // Check if caller wants data or attributes
            id returnType = dict[(__bridge id)kSecReturnData];
            if ([returnType boolValue]) {
                NSData *data = [fakeValue dataUsingEncoding:NSUTF8StringEncoding];
                *result = CFBridgingRetain(data);
            } else {
                *result = CFBridgingRetain(fakeValue);
            }
        }
        return errSecSuccess;
    }
}
// ============================================================
#pragma mark — Phase 1: SecItemDelete hook
// ============================================================
static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    @autoreleasepool {
        if (!ytkPlusFound) return real_SecItemDelete(query);

        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *service = dict[(__bridge id)kSecAttrService];

        if ([service isEqualToString:kService]) {
            NSString *account = dict[(__bridge id)kSecAttrAccount];
            LOG(@"SecItemDelete BLOCKED: %@", account ?: @"(all)");
            return errSecSuccess; // pretend success
        }
        return real_SecItemDelete(query);
    }
}
// ============================================================
#pragma mark — Phase 1: SecItemAdd hook
// ============================================================
static OSStatus hook_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @autoreleasepool {
        if (!ytkPlusFound) return real_SecItemAdd(attributes, result);

        NSDictionary *dict = (__bridge NSDictionary *)attributes;
        NSString *service = dict[(__bridge id)kSecAttrService];

        if ([service isEqualToString:kService]) {
            NSString *account = dict[(__bridge id)kSecAttrAccount];
            LOG(@"SecItemAdd BLOCKED: %@", account ?: @"(unknown)");
            if (result) *result = NULL;
            return errSecSuccess; // pretend success
        }
        return real_SecItemAdd(attributes, result);
    }
}

// Register the interpose entries — dyld will swap pointers at load time
DYLD_INTERPOSE(hook_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(hook_SecItemDelete, SecItemDelete)
DYLD_INTERPOSE(hook_SecItemAdd, SecItemAdd)
// ============================================================
#pragma mark — Phase 1: UIViewController presentViewController hook
// ============================================================
static void (*orig_presentVC)(UIViewController *, SEL, UIViewController *, BOOL, id);
static void hook_presentVC(UIViewController *self, SEL _cmd,
                           UIViewController *vc, BOOL animated, id completion) {
    if (!ytkPlusFound) {
        orig_presentVC(self, _cmd, vc, animated, completion);
        return;
    }
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title   = alert.title   ?: @"";
        NSString *message = alert.message ?: @"";

        // Suppress YTKPlus license-related alerts
        if ([title containsString:@"license_verification"] ||
            [title containsString:@"verification_passed"] ||
            [title containsString:@"license_verification_passed"] ||
            [message containsString:@"Invalid key"] ||
            [message containsString:@"Invalid signature"] ||
            [message containsString:@"license_expired"] ||
            [message containsString:@"License Options"]) {
            LOG(@"SUPPRESSED alert: title=\"%@\" message=\"%@\"", title, message);
            return; // swallow the alert
        }
    }
    orig_presentVC(self, _cmd, vc, animated, completion);
}
// ============================================================
#pragma mark — Phase 2: FUN_00046d48 hook (seal validator → return 0)
// ============================================================
// FUN_00046d48 signature: byte FUN_00046d48(long,long,long,long,long,ID)
// Returning 0 prevents the server verification call in checkAuthenticationStatusAndProceed.
// Returning 1 would CAUSE the server call → "Invalid key" popup.
static uint8_t (*orig_FUN_00046d48)(long, long, long, long, long, void *);
static uint8_t hook_FUN_00046d48(long p1, long p2, long p3, long p4, long p5, void *p6) {
    LOG(@"FUN_00046d48 called → returning 0 (prevents server verify call)");
    return 0;
}
// ============================================================
#pragma mark — Phase 3: Settings page hooks
// ============================================================
static void (*orig_settingsVerifyYkChecker)(id, SEL, id);
static void hook_settingsVerifyYkChecker(id self, SEL _cmd, id param) {
    LOG(@"settingsVerifyYkChecker_ intercepted → presenting RootOptionsController");

    Class rootOptsClass = NSClassFromString(@"RootOptionsController");
    if (!rootOptsClass) {
        LOG(@"RootOptionsController class not found!");
        return;
    }

    // Create settings VC (UITableViewController with grouped style)
    UITableViewController *settingsVC = [[rootOptsClass alloc] initWithStyle:UITableViewStyleGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settingsVC];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;

    [self presentViewController:nav animated:YES completion:nil];
    LOG(@"RootOptionsController presented successfully");
}
static void (*orig_openCheckLicense)(id, SEL);
static void hook_openCheckLicense(id self, SEL _cmd) {
    LOG(@"openCheckLicense intercepted → redirecting to settings");
    hook_settingsVerifyYkChecker(self, _cmd, nil);
}
// ============================================================
#pragma mark — Dyld image callback (Phase 2)
// ============================================================
static void dyld_callback(const struct mach_header *mh, intptr_t slide) {
    @try {
        Dl_info info;
        if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;

        NSString *path = [NSString stringWithUTF8String:info.dli_fname];
        if (![path containsString:@"YTKPlus"]) return;

        LOG(@"=== Phase 2: YTKPlus found at %s (slide=0x%lx) ===", info.dli_fname, (long)slide);

        ytkPlusFound = YES;
        uintptr_t base = (uintptr_t)mh;

        // Validate mach-o magic before hooking to prevent crashes from wrong binary
        uint32_t magic = *(uint32_t *)mh;
        if (magic != MH_MAGIC_64 && magic != MH_MAGIC) {
            LOG(@"WARNING: Invalid mach-o magic 0x%x — skipping hook", magic);
            return;
        }

        void *fn_46d48 = (void *)(base + 0x46d48);
        if (fn_46d48) {
            MSHookFunction(fn_46d48, (void *)hook_FUN_00046d48, (void **)&orig_FUN_00046d48);
            LOG(@"Hooked FUN_00046d48 at %p → returns 0", fn_46d48);
        }

    // Phase 3: Delayed hooks for runtime classes
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        LOG(@"=== Phase 3: Installing settings hooks ===");

        Class dlClass = NSClassFromString(@"DownloadsController");
        if (dlClass) {
            // Hook settingsVerifyYkChecker: → present settings directly
            SEL selVerify = NSSelectorFromString(@"settingsVerifyYkChecker:");
            if ([dlClass instancesRespondToSelector:selVerify]) {
                MSHookMessageEx(dlClass, selVerify,
                                (IMP)hook_settingsVerifyYkChecker,
                                (IMP *)&orig_settingsVerifyYkChecker);
                LOG(@"Hooked DownloadsController settingsVerifyYkChecker:");
            } else {
                LOG(@"WARNING: settingsVerifyYkChecker: not found on DownloadsController");
            }

            // Hook openCheckLicense → redirect to settings
            SEL selCheck = NSSelectorFromString(@"openCheckLicense");
            if ([dlClass instancesRespondToSelector:selCheck]) {
                MSHookMessageEx(dlClass, selCheck,
                                (IMP)hook_openCheckLicense,
                                (IMP *)&orig_openCheckLicense);
                LOG(@"Hooked DownloadsController openCheckLicense");
            }
        } else {
            LOG(@"WARNING: DownloadsController class not found");
        }

        // Also hook on DownloadsController2 if it exists
        Class dlClass2 = NSClassFromString(@"DownloadsController2");
        if (dlClass2) {
            SEL selVerify = NSSelectorFromString(@"settingsVerifyYkChecker:");
            if ([dlClass2 instancesRespondToSelector:selVerify]) {
                MSHookMessageEx(dlClass2, selVerify,
                                (IMP)hook_settingsVerifyYkChecker, NULL);
                LOG(@"Hooked DownloadsController2 settingsVerifyYkChecker:");
            }
            SEL selCheck = NSSelectorFromString(@"openCheckLicense");
            if ([dlClass2 instancesRespondToSelector:selCheck]) {
                MSHookMessageEx(dlClass2, selCheck,
                                (IMP)hook_openCheckLicense, NULL);
                LOG(@"Hooked DownloadsController2 openCheckLicense");
            }
        }

        LOG(@"=== Phase 3 complete ===");

        // One-time welcome popup on first detection
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        if (![defaults boolForKey:kFirstRunKey]) {
            [defaults setBool:YES forKey:kFirstRunKey];
            [defaults synchronize];

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                UIAlertController *welcome = [UIAlertController
                    alertControllerWithTitle:@"YTKActivator"
                    message:@"YTKPlus has been activated successfully.\n\nMade by itzzace"
                    preferredStyle:UIAlertControllerStyleAlert];
                [welcome addAction:[UIAlertAction actionWithTitle:@"OK"
                                    style:UIAlertActionStyleDefault handler:nil]];

                UIWindowScene *ws = nil;
                for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
                    if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
                }
                UIViewController *topVC = nil;
                for (UIWindow *w in ws.windows) {
                    if (w.isKeyWindow) { topVC = w.rootViewController; break; }
                }
                while (topVC.presentedViewController) topVC = topVC.presentedViewController;
                if (topVC) [topVC presentViewController:welcome animated:YES completion:nil];

                LOG(@"First-run welcome popup shown");
            });
        }
    });

    LOG(@"=== Phase 2 complete ===");
    } @catch (NSException *e) {
        LOG(@"Phase 2 exception: %@", e);
    }
}
// ============================================================
#pragma mark — Constructor (Phase 1)
// ============================================================
__attribute__((constructor))
static void init() {
    @try {
        LOG(@"=== Phase 1: Initializing (DYLD_INTERPOSE active) ===");

        // SecItem hooks are installed via DYLD_INTERPOSE at load time (no code patching).
        // Just resolve the real function pointers so we can call them.
        resolveRealSecItem();
        LOG(@"SecItem real ptrs: copy=%p del=%p add=%p",
            real_SecItemCopyMatching, real_SecItemDelete, real_SecItemAdd);

        // Hook UIViewController presentViewController — ObjC swizzle (safe, no code mod)
        Class vcClass = [UIViewController class];
        if (vcClass) {
            MSHookMessageEx(vcClass,
                            @selector(presentViewController:animated:completion:),
                            (IMP)hook_presentVC,
                            (IMP *)&orig_presentVC);
            LOG(@"Hooked UIViewController presentViewController:animated:completion:");
        }

        // Register dyld callback for Phase 2
        _dyld_register_func_for_add_image(dyld_callback);
        LOG(@"Registered dyld callback");

        LOG(@"=== Phase 1 complete ===");
    } @catch (NSException *e) {
        LOG(@"Phase 1 EXCEPTION: %@ — tweak disabled", e);
    }
}
