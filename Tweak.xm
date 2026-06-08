/*
 *  YTKActivator v16 — Substrate-FREE for iOS 26 compatibility
 *
 *  iOS 26 changes:
 *    - CydiaSubstrate crashes on load (KERN_PROTECTION_FAILURE)
 *    - MSHookFunction modifies code pages → SIGKILL by code signing monitor
 *
 *  This build uses ZERO substrate APIs:
 *    - SecItem hooks → DYLD_INTERPOSE (pure dyld metadata, no code patching)
 *    - ObjC hooks → method_exchangeImplementations (modifies method table only)
 *    - No FUN_xxxx binary patches (rely on keychain values alone for bVar1)
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
#define LOG(fmt, ...) NSLog(@"[YTKBypass] " fmt, ##__VA_ARGS__)

// ============================================================
#pragma mark — Constants
// ============================================================
static NSString *const kService = @"me.ikghd.ytkplus.secure";
static NSString *const kFirstRunKey = @"com.itzzace.ytkactivator.firstRun";
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

// Diagnostic counters
static _Atomic int hook_copy_count = 0;
static _Atomic int hook_copy_ytk_count = 0;
static _Atomic int hook_delete_count = 0;
static _Atomic int hook_add_count = 0;
static NSMutableArray *seenAccounts = nil;

// ============================================================
#pragma mark — DYLD_INTERPOSE macro
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

// ============================================================
#pragma mark — Real SecItem function pointers
// ============================================================
static OSStatus (*real_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *) = NULL;
static OSStatus (*real_SecItemDelete)(CFDictionaryRef) = NULL;
static OSStatus (*real_SecItemAdd)(CFDictionaryRef, CFTypeRef *) = NULL;

static void resolveRealSecItem(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemCopyMatching");
        real_SecItemDelete       = (OSStatus (*)(CFDictionaryRef))dlsym(RTLD_NEXT, "SecItemDelete");
        real_SecItemAdd          = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))dlsym(RTLD_NEXT, "SecItemAdd");
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
#pragma mark — SecItem hooks (interposed)
// ============================================================

static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    @autoreleasepool {
        if (!real_SecItemCopyMatching) resolveRealSecItem();
        hook_copy_count++;
        if (!ytkPlusFound) return real_SecItemCopyMatching(query, result);

        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *service = dict[(__bridge id)kSecAttrService];
        if (![service isEqualToString:kService]) {
            return real_SecItemCopyMatching(query, result);
        }

        hook_copy_ytk_count++;
        NSString *account = dict[(__bridge id)kSecAttrAccount];
        if (account && seenAccounts && ![seenAccounts containsObject:account] && seenAccounts.count < 30) {
            @synchronized(seenAccounts) {
                if (![seenAccounts containsObject:account]) [seenAccounts addObject:account];
            }
        }

        // Keys that must return nil to skip HMAC checks
        if ([account isEqualToString:kAuthSeal] || [account isEqualToString:kAuthLastSeal]) {
            if (result) *result = NULL;
            return errSecItemNotFound;
        }

        NSString *fakeValue = nil;
        if      ([account isEqualToString:kAuthEmail])        fakeValue = @"bypass@ytk.local";
        else if ([account isEqualToString:kAuthLicense])      fakeValue = @"BYPASS-0000-0000-0000";
        else if ([account isEqualToString:kAuthDevice])       fakeValue = @"FAKEDEVICE-BYPASS-V16";
        else if ([account isEqualToString:kAuthExpires])      fakeValue = @"01-01-2030 12:00 AM";
        else if ([account isEqualToString:kAuthSessionToken]) fakeValue = @"FAKETOKEN-BYPASS-V16";
        else if ([account isEqualToString:kAuthTimestamp])    fakeValue = @"9999999999";
        else                                                  fakeValue = @"1";

        if (result) {
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

static OSStatus hook_SecItemDelete(CFDictionaryRef query) {
    @autoreleasepool {
        if (!real_SecItemDelete) resolveRealSecItem();
        hook_delete_count++;
        if (!ytkPlusFound) return real_SecItemDelete(query);

        NSDictionary *dict = (__bridge NSDictionary *)query;
        NSString *service = dict[(__bridge id)kSecAttrService];
        if ([service isEqualToString:kService]) {
            return errSecSuccess; // block
        }
        return real_SecItemDelete(query);
    }
}

static OSStatus hook_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    @autoreleasepool {
        if (!real_SecItemAdd) resolveRealSecItem();
        hook_add_count++;
        if (!ytkPlusFound) return real_SecItemAdd(attributes, result);

        NSDictionary *dict = (__bridge NSDictionary *)attributes;
        NSString *service = dict[(__bridge id)kSecAttrService];
        if ([service isEqualToString:kService]) {
            if (result) *result = NULL;
            return errSecSuccess; // block
        }
        return real_SecItemAdd(attributes, result);
    }
}

DYLD_INTERPOSE(hook_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(hook_SecItemDelete,        SecItemDelete)
DYLD_INTERPOSE(hook_SecItemAdd,           SecItemAdd)

// ============================================================
#pragma mark — Native ObjC swizzle helper (no substrate)
// ============================================================
static BOOL swizzleInstanceMethod(Class cls, SEL originalSel, IMP newImp, IMP *origImpOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, originalSel);
    if (!m) return NO;
    IMP previous = method_setImplementation(m, newImp);
    if (origImpOut) *origImpOut = previous;
    return YES;
}

// ============================================================
#pragma mark — UIViewController presentViewController swizzle
// ============================================================
static void (*orig_presentVC)(id, SEL, id, BOOL, id) = NULL;
static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if (ytkPlusFound && [vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title   = alert.title   ?: @"";
        NSString *message = alert.message ?: @"";
        if ([title containsString:@"license_verification"] ||
            [title containsString:@"verification_passed"] ||
            [message containsString:@"Invalid key"] ||
            [message containsString:@"Invalid signature"] ||
            [message containsString:@"license_expired"] ||
            [message containsString:@"License Options"]) {
            LOG(@"Suppressed alert: %@", title);
            return; // swallow
        }
    }
    if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark — Settings page swizzle
// ============================================================
static void hook_settingsVerifyYkChecker(id self, SEL _cmd, id sender) {
    Class rootOptsClass = NSClassFromString(@"RootOptionsController");
    if (!rootOptsClass) return;
    UITableViewController *settingsVC = [[rootOptsClass alloc] initWithStyle:UITableViewStyleGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:settingsVC];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:nav animated:YES completion:nil];
}

static void hook_openCheckLicense(id self, SEL _cmd) {
    hook_settingsVerifyYkChecker(self, _cmd, nil);
}

// ============================================================
#pragma mark — Force "Active" state in settings page
// ============================================================
// Walks the cell after the original configures it, forces switch ON
// and rewrites any "Inactive" / "Verify License" labels to green "Active"
static void forceCellActive(UITableViewCell *cell) {
    if (!cell) return;

    // Find UISwitch in accessoryView
    if ([cell.accessoryView isKindOfClass:[UISwitch class]]) {
        UISwitch *sw = (UISwitch *)cell.accessoryView;
        [sw setOn:YES animated:NO];
        sw.enabled = YES;
    }
    // Walk all subviews recursively
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
            NSString *text = lbl.text ?: @"";
            NSString *lower = text.lowercaseString;
            if ([lower containsString:@"inactive"] ||
                [lower containsString:@"verify license"] ||
                [lower containsString:@"not verified"] ||
                [lower containsString:@"disabled"] ||
                [lower containsString:@"not active"]) {
                lbl.text = @"Active (Verified)";
                lbl.textColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.2 alpha:1.0];
            }
        }
    }
}

static void (*orig_configureEnabledCell)(id, SEL, id) = NULL;
static void hook_configureEnabledCell(id self, SEL _cmd, id cell) {
    if (orig_configureEnabledCell) {
        orig_configureEnabledCell(self, _cmd, cell);
    }
    if ([cell isKindOfClass:[UITableViewCell class]]) {
        forceCellActive((UITableViewCell *)cell);
        // Also patch again on next runloop in case YTKPlus updates async
        dispatch_async(dispatch_get_main_queue(), ^{
            forceCellActive((UITableViewCell *)cell);
        });
    }
}

// Also hook tableView:cellForRowAtIndexPath: as a catch-all
static UITableViewCell *(*orig_cellForRowAtIndexPath)(id, SEL, UITableView *, NSIndexPath *) = NULL;
static UITableViewCell *hook_cellForRowAtIndexPath(id self, SEL _cmd,
                                                    UITableView *tv, NSIndexPath *ip) {
    UITableViewCell *cell = orig_cellForRowAtIndexPath
        ? orig_cellForRowAtIndexPath(self, _cmd, tv, ip)
        : nil;
    forceCellActive(cell);
    return cell;
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

        LOG(@"YTKPlus.dylib loaded — SecItem interpose will fake activation");
        ytkPlusFound = YES;

        // Phase 3: Wait for YTKPlus constructor to create runtime classes, then swizzle
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            Class dc = NSClassFromString(@"DownloadsController");
            if (dc) {
                IMP origIgnored = NULL;
                swizzleInstanceMethod(dc, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                      (IMP)hook_settingsVerifyYkChecker, &origIgnored);
                swizzleInstanceMethod(dc, NSSelectorFromString(@"openCheckLicense"),
                                      (IMP)hook_openCheckLicense, &origIgnored);
                LOG(@"DownloadsController swizzled");
            }

            Class dc2 = NSClassFromString(@"DownloadsController2");
            if (dc2) {
                IMP origIgnored = NULL;
                swizzleInstanceMethod(dc2, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                      (IMP)hook_settingsVerifyYkChecker, &origIgnored);
                swizzleInstanceMethod(dc2, NSSelectorFromString(@"openCheckLicense"),
                                      (IMP)hook_openCheckLicense, &origIgnored);
                LOG(@"DownloadsController2 swizzled");
            }

            // Force settings cells to show "Active"
            Class roc = NSClassFromString(@"RootOptionsController");
            if (roc) {
                swizzleInstanceMethod(roc,
                    NSSelectorFromString(@"configureEnabledCell:"),
                    (IMP)hook_configureEnabledCell,
                    (IMP *)&orig_configureEnabledCell);
                swizzleInstanceMethod(roc,
                    @selector(tableView:cellForRowAtIndexPath:),
                    (IMP)hook_cellForRowAtIndexPath,
                    (IMP *)&orig_cellForRowAtIndexPath);
                LOG(@"RootOptionsController cell forcing installed");
            }

            // Diagnostic popup (always shows for now to debug feature issues)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                NSString *accountList = seenAccounts.count > 0
                    ? [seenAccounts componentsJoinedByString:@"\n  "]
                    : @"(none — interpose not working!)";
                NSString *msg = [NSString stringWithFormat:
                    @"v18 Diagnostics\n\n"
                    @"SecItemCopyMatching total: %d\n"
                    @"  → for YTK service: %d\n"
                    @"SecItemDelete total: %d\n"
                    @"SecItemAdd total: %d\n\n"
                    @"YTK accounts queried:\n  %@\n\n"
                    @"Made by itzzace",
                    hook_copy_count, hook_copy_ytk_count,
                    hook_delete_count, hook_add_count,
                    accountList];

                UIAlertController *welcome = [UIAlertController
                    alertControllerWithTitle:@"YTKActivator Debug"
                    message:msg
                    preferredStyle:UIAlertControllerStyleAlert];
                [welcome addAction:[UIAlertAction actionWithTitle:@"Copy"
                                    style:UIAlertActionStyleDefault
                                    handler:^(UIAlertAction *a) {
                    [UIPasteboard generalPasteboard].string = msg;
                }]];
                [welcome addAction:[UIAlertAction actionWithTitle:@"OK"
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
                                       welcome, YES, nil);
                    } else {
                        [topVC presentViewController:welcome animated:YES completion:nil];
                    }
                }
            });
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
        LOG(@"=== v18 substrate-free init + diagnostics ===");
        seenAccounts = [NSMutableArray new];

        // Resolve real SecItem pointers (interposers are auto-installed by dyld)
        resolveRealSecItem();
        LOG(@"SecItem real ptrs: copy=%p del=%p add=%p",
            real_SecItemCopyMatching, real_SecItemDelete, real_SecItemAdd);

        // Swizzle UIViewController presentViewController:animated:completion:
        Class vcClass = [UIViewController class];
        if (vcClass) {
            swizzleInstanceMethod(vcClass,
                                  @selector(presentViewController:animated:completion:),
                                  (IMP)hook_presentVC, (IMP *)&orig_presentVC);
            LOG(@"UIViewController.presentViewController swizzled");
        }

        // Register dyld callback for YTKPlus detection
        _dyld_register_func_for_add_image(dyld_callback);
        LOG(@"dyld callback registered");

        LOG(@"=== v16 init complete ===");
    } @catch (NSException *e) {
        LOG(@"init EXCEPTION: %@", e);
    }
}
