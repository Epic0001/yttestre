/*
 *  YTKActivator v1.8 — Minimal preseed-only
 *
 *  No swizzles, no popups, no settings UI hacks. Just write keychain
 *  values that YTKPlus 5.6.1 needs to skip activation/stats POSTs and
 *  treat itself as activated. First launch writes keychain then exits;
 *  user reopens and YTK reads the preseeded values.
 *
 *  Made by itzzace
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

#define LOG(fmt, ...) NSLog(@"[YTKActivator] " fmt, ##__VA_ARGS__)

static NSString *const kService     = @"me.ikghd.ytkplus.secure";
static NSString *const kFakeLicense = @"ACTIVATED-0000-0000";
static NSString *const kYTKVersion  = @"5.6.1";

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

    // Identity
    writeKeychainValue(@"auth_email_secure",    @"activated@ytk.local");
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   @"YTKActivator");
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   @"YTKActivator-Token");
    writeKeychainValue(@"auth_timestamp",       @"9999999999");

    // 5.6.1 gate keys: skip activation/stats POSTs
    writeKeychainValue(@"activation_logged_for_key", kFakeLicense);
    writeKeychainValue(@"lastStatsReportedVersion",  kYTKVersion);

    // Clear seals so YTK doesn't try to verify against an old seal
    writeKeychainValue(@"auth_integrity_seal",       nil);
    writeKeychainValue(@"auth_last_verified_seal",   nil);
    writeKeychainValue(@"auth_last_verified_ts",     nil);
    writeKeychainValue(@"ytk_last_contact_seal",     nil);
    writeKeychainValue(@"ytk_last_contact_ts",       nil);

    LOG(@"Keychain pre-seeded");
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();
    LOG(@"YTKActivator v1.8 loaded (minimal)");

    // First-launch: write keychain, then exit so YTK reads preseeded values next time
    NSString *flagKey = @"com.itzzace.ytkactivator.firstLaunchDone.v18";
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (![d boolForKey:flagKey]) {
        [d setBool:YES forKey:flagKey];
        [d synchronize];
        LOG(@"First launch — exiting in 1s so next launch activates clean");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            exit(0);
        });
    }
}
