/*
 *  YTKActivator v1.7 — No-interpose, aggressive preseed strategy
 *
 *  Strategy: write keychain values multiple times so they persist for
 *  YTKPlus's next launch. First launch shows popup then exits, second
 *  launch onward activates fully. Includes 5.6.1-specific gate keys
 *  (activation_logged_for_key, lastStatsReportedVersion) to skip the
 *  "Service unavailable" server check.
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define LOG(fmt, ...) NSLog(@"[YTKActivator] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";

// ============================================================
#pragma mark — ObjC swizzle helper
// ============================================================
static BOOL swizzleInstanceMethod(Class cls, SEL sel, IMP newImp, IMP *origOut) {
    if (!cls) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    IMP prev = method_setImplementation(m, newImp);
    if (origOut) *origOut = prev;
    return YES;
}

// ============================================================
#pragma mark — Alert suppression
// ============================================================
static void (*orig_presentVC)(id, SEL, id, BOOL, id) = NULL;

static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if ([vc isKindOfClass:[UIAlertController class]]) {
        UIAlertController *alert = (UIAlertController *)vc;
        NSString *title   = alert.title   ?: @"";
        NSString *message = alert.message ?: @"";
        if ([title containsString:@"license_verification"] ||
            [title containsString:@"verification_passed"] ||
            [title containsString:@"YTKillerPlus"] ||
            [message containsString:@"Invalid key"] ||
            [message containsString:@"Invalid signature"] ||
            [message containsString:@"license_expired"] ||
            [message containsString:@"License Options"] ||
            [message containsString:@"team_verification"] ||
            [message containsString:@"Service unavailable"] ||
            [message containsString:@"Incompatible environment"] ||
            [message containsString:@"incompatible environment"]) {
            return;
        }
    }
    if (orig_presentVC) orig_presentVC(self, _cmd, vc, animated, completion);
}

// ============================================================
#pragma mark — Settings page bypass
// ============================================================
static void hook_settingsVerifyYkChecker(id self, SEL _cmd, id sender) {
    Class rootOptsClass = NSClassFromString(@"RootOptionsController");
    if (!rootOptsClass) return;
    UITableViewController *vc = [[rootOptsClass alloc] initWithStyle:UITableViewStyleGrouped];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;
    [self presentViewController:nav animated:YES completion:nil];
}

static void hook_openCheckLicense(id self, SEL _cmd) {
    hook_settingsVerifyYkChecker(self, _cmd, nil);
}

// ============================================================
#pragma mark — Force settings cells active
// ============================================================
static void forceCellActive(UITableViewCell *cell) {
    if (!cell) return;
    if ([cell.accessoryView isKindOfClass:[UISwitch class]]) {
        [(UISwitch *)cell.accessoryView setOn:YES animated:NO];
        ((UISwitch *)cell.accessoryView).enabled = YES;
    }
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
            NSString *lower = (lbl.text ?: @"").lowercaseString;
            if ([lower containsString:@"inactive"] ||
                [lower containsString:@"verify license"] ||
                [lower containsString:@"not verified"] ||
                [lower containsString:@"disabled"] ||
                [lower containsString:@"not active"]) {
                lbl.text = @"Active";
                lbl.textColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.2 alpha:1.0];
            }
        }
    }
}

static void (*orig_configureEnabledCell)(id, SEL, id) = NULL;
static void hook_configureEnabledCell(id self, SEL _cmd, id cell) {
    if (orig_configureEnabledCell) orig_configureEnabledCell(self, _cmd, cell);
    if ([cell isKindOfClass:[UITableViewCell class]]) {
        forceCellActive((UITableViewCell *)cell);
        dispatch_async(dispatch_get_main_queue(), ^{
            forceCellActive((UITableViewCell *)cell);
        });
    }
}

static UITableViewCell *(*orig_cellForRow)(id, SEL, UITableView *, NSIndexPath *) = NULL;
static UITableViewCell *hook_cellForRow(id self, SEL _cmd, UITableView *tv, NSIndexPath *ip) {
    UITableViewCell *cell = orig_cellForRow ? orig_cellForRow(self, _cmd, tv, ip) : nil;
    forceCellActive(cell);
    return cell;
}

// ============================================================
#pragma mark — Keychain pre-seed (direct, no hooks)
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
        (__bridge id)kSecClass:         (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService:   kService,
        (__bridge id)kSecAttrAccount:   account,
        (__bridge id)kSecValueData:     [value dataUsingEncoding:NSUTF8StringEncoding],
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock,
    };
    SecItemAdd((__bridge CFDictionaryRef)addQuery, NULL);
}

static void preseedKeychain(void) {
    // Activation flags
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    // License identity
    writeKeychainValue(@"auth_email_secure",    @"activated@ytk.local");
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   @"YTKActivator");
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   @"YTKActivator-Token");
    writeKeychainValue(@"auth_timestamp",       @"9999999999");

    // 5.6.1 gate keys — skip activation + stats POST calls
    // FUN_0003db08: activation network call only fires if license != activation_logged_for_key
    // FUN_0003d334: stats network call only fires if lastStatsReportedVersion != current YTK version
    writeKeychainValue(@"activation_logged_for_key", kFakeLicense);
    writeKeychainValue(@"lastStatsReportedVersion",  kYTKVersion);

    // Seal/timestamp keys must NOT exist (HMAC mismatch otherwise → server reject)
    writeKeychainValue(@"auth_integrity_seal",       nil);
    writeKeychainValue(@"auth_last_verified_seal",   nil);
    writeKeychainValue(@"auth_last_verified_ts",     nil);
    writeKeychainValue(@"ytk_last_contact_seal",     nil);
    writeKeychainValue(@"ytk_last_contact_ts",       nil);
    LOG(@"Keychain pre-seeded");
}

// ============================================================
#pragma mark — Welcome popup
// ============================================================
static void showWelcomeIfNeeded(void) {
    NSString *key = @"com.itzzace.ytkactivator.version";
    NSString *ver = @"1.7";
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if ([[d stringForKey:key] isEqualToString:ver]) return;
    [d setObject:ver forKey:key];
    [d synchronize];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"YTKActivator"
            message:@"YTKPlus activation written.\n\nIf premium features don't work yet, force-close YouTube and reopen.\n\nMade by itzzace"
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
        UIWindowScene *ws = nil;
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes)
            if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
        UIViewController *top = nil;
        for (UIWindow *w in ws.windows)
            if (w.isKeyWindow) { top = w.rootViewController; break; }
        while (top.presentedViewController) top = top.presentedViewController;
        if (top) {
            if (orig_presentVC) orig_presentVC(top, @selector(presentViewController:animated:completion:), alert, YES, nil);
            else [top presentViewController:alert animated:YES completion:nil];
        }
    });
}

// ============================================================
#pragma mark — Dyld callback
// ============================================================
static void dyld_callback(const struct mach_header *mh, intptr_t slide) {
    Dl_info info;
    if (!dladdr((const void *)mh, &info) || !info.dli_fname) return;
    if (!strstr(info.dli_fname, "YTKPlus")) return;

    LOG(@"YTKPlus detected — re-preseeding for next launch");
    preseedKeychain();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        Class dc = NSClassFromString(@"DownloadsController");
        if (dc) {
            IMP ign = NULL;
            swizzleInstanceMethod(dc, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                  (IMP)hook_settingsVerifyYkChecker, &ign);
            swizzleInstanceMethod(dc, NSSelectorFromString(@"openCheckLicense"),
                                  (IMP)hook_openCheckLicense, &ign);
        }
        Class dc2 = NSClassFromString(@"DownloadsController2");
        if (dc2) {
            IMP ign = NULL;
            swizzleInstanceMethod(dc2, NSSelectorFromString(@"settingsVerifyYkChecker:"),
                                  (IMP)hook_settingsVerifyYkChecker, &ign);
            swizzleInstanceMethod(dc2, NSSelectorFromString(@"openCheckLicense"),
                                  (IMP)hook_openCheckLicense, &ign);
        }
        Class roc = NSClassFromString(@"RootOptionsController");
        if (roc) {
            swizzleInstanceMethod(roc, NSSelectorFromString(@"configureEnabledCell:"),
                                  (IMP)hook_configureEnabledCell, (IMP *)&orig_configureEnabledCell);
            swizzleInstanceMethod(roc, @selector(tableView:cellForRowAtIndexPath:),
                                  (IMP)hook_cellForRow, (IMP *)&orig_cellForRow);
        }

        // Re-seed once more after YTK is settled
        preseedKeychain();

        showWelcomeIfNeeded();
    });
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();

    swizzleInstanceMethod([UIViewController class],
                          @selector(presentViewController:animated:completion:),
                          (IMP)hook_presentVC, (IMP *)&orig_presentVC);

    _dyld_register_func_for_add_image(dyld_callback);

    LOG(@"YTKActivator v1.7 loaded");

    // First-launch auto-restart: show popup, then exit so next launch activates cleanly
    NSString *flagKey = @"com.itzzace.ytkactivator.firstLaunchDone";
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (![d boolForKey:flagKey]) {
        [d setBool:YES forKey:flagKey];
        [d synchronize];
        LOG(@"First launch — showing popup then exiting");

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController
                alertControllerWithTitle:@"YTKActivated"
                message:@"Closing in 5 seconds...\n\nReopen YouTube after the app closes to activate all premium features."
                preferredStyle:UIAlertControllerStyleAlert];

            UIWindowScene *ws = nil;
            for (UIScene *s in [UIApplication sharedApplication].connectedScenes)
                if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
            UIViewController *top = nil;
            for (UIWindow *w in ws.windows)
                if (w.isKeyWindow) { top = w.rootViewController; break; }
            while (top.presentedViewController) top = top.presentedViewController;
            if (top) {
                if (orig_presentVC) orig_presentVC(top, @selector(presentViewController:animated:completion:), alert, YES, nil);
                else [top presentViewController:alert animated:YES completion:nil];
            }

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                exit(0);
            });
        });
    }
}
