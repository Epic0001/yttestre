/*
 *  YTKHelper / YTKActivator v2.2 — preseed + credit popup
 *
 *  Same v2.1 keychain logic (force-fail seal verifier, empty banlists)
 *  + 5s delay credit popup on first launch saying "App is crashing,
 *  please reopen when it crashes" then exits so launch 2 activates clean.
 *
 *  Built twice via GitHub Actions:
 *    - YTKHelper.dylib  (current safe name)
 *    - YTKActivator.dylib (legacy name, in case you need the old one)
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

#define LOG(fmt, ...) NSLog(@"[YTKHelper] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";
static NSString *const kJunkSeal    = @"INVALID-SEAL-FORCE-VERIFY-FAIL";
static NSString *const kFutureTs    = @"9999999999.000";

// ============================================================
#pragma mark — Keychain pre-seed
// ============================================================
// Match YTK's attributes exactly (FUN_47440 in decomp):
//   kSecAttrAccessible: AfterFirstUnlockThisDeviceOnly
//   kSecAttrSynchronizable: NO
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
    // Activation flags
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    // Identity
    writeKeychainValue(@"auth_email_secure",    @"activated@ytk.local");
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   @"YTKHelper");
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   @"YTKHelper-Token");
    writeKeychainValue(@"auth_timestamp",       @"9999999999");

    // 5.6.1 gate keys
    writeKeychainValue(@"activation_logged_for_key", kFakeLicense);
    writeKeychainValue(@"lastStatsReportedVersion",  kYTKVersion);

    // Empty banlists
    writeKeychainValue(@"ytk_rc_cache",            @"{\"bannedUUIDs\":[],\"bannedDylibs\":[]}");
    writeKeychainValue(@"ytk_banned_uuids",        @"[]");
    writeKeychainValue(@"ytk_banned_dylib_names",  @"[]");

    // Force-fail seal verifier (banlist refetch)
    writeKeychainValue(@"ytk_last_contact_ts",   kFutureTs);
    writeKeychainValue(@"ytk_last_contact_seal", kJunkSeal);

    // Force-fail seal verifier (activation refetch)
    writeKeychainValue(@"auth_last_verified_ts",   kFutureTs);
    writeKeychainValue(@"auth_last_verified_seal", kJunkSeal);

    // Clear integrity seal
    writeKeychainValue(@"auth_integrity_seal", nil);

    LOG(@"Keychain pre-seeded (v2.2)");
}

// ============================================================
#pragma mark — Credit popup
// ============================================================
static void showCreditPopupAndExit(void) {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"YTKActivated"
        message:@"App is crashing — please reopen when it crashes.\n\nMade by itzzace"
        preferredStyle:UIAlertControllerStyleAlert];

    UIWindowScene *ws = nil;
    for (UIScene *s in [UIApplication sharedApplication].connectedScenes)
        if ([s isKindOfClass:[UIWindowScene class]]) { ws = (UIWindowScene *)s; break; }
    UIViewController *top = nil;
    for (UIWindow *w in ws.windows)
        if (w.isKeyWindow) { top = w.rootViewController; break; }
    while (top.presentedViewController) top = top.presentedViewController;
    if (top) [top presentViewController:alert animated:YES completion:nil];

    // Exit 5s after popup appears
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        exit(0);
    });
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();
    LOG(@"YTKHelper v2.2 loaded");

    NSString *flagKey = @"com.itzzace.ytkhelper.firstLaunchDone.v22";
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (![d boolForKey:flagKey]) {
        [d setBool:YES forKey:flagKey];
        [d synchronize];
        LOG(@"First launch — showing credit popup, exiting in 5s");

        // Wait 5s for UI to be ready, then show popup + exit
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            showCreditPopupAndExit();
        });
    }
}
