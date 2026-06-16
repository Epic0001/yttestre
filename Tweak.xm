/*
 *  YTKHelper v2.1 — Force-fail seal verifier to disable banlist refetch
 *
 *  Discovery: YTKPlus 5.6.1 has buggy logic in its "should I refetch banlist"
 *  decider (FUN_3cbb8). When the seal verifier (FUN_44e94) returns 0 (failed),
 *  the XOR truth-table logic SKIPS the network refetch instead of forcing it.
 *
 *  So we:
 *    1. Match YTK's exact keychain attributes (AfterFirstUnlockThisDeviceOnly +
 *       Synchronizable=NO) so our presed items collide with YTK's own writes
 *       instead of coexisting as phantom items
 *    2. Preseed garbage seals → verifier returns 0 → no banlist refetch ever
 *    3. Preseed empty banlists → name-of-dylib check finds nothing
 *    4. Same trick for auth_last_verified_seal → no activation refetch
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
// Otherwise our writes create phantom items YTK never reads.
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
    // ---- Activation flags ----
    writeKeychainValue(@"Etmvdvihq chmhc rml", @"1");
    writeKeychainValue(@"Enabledytk_status",    @"1");
    writeKeychainValue(@"auth_status_secure",   @"1");
    writeKeychainValue(@"activation_logged",    @"1");
    writeKeychainValue(@"stats_sent_before",    @"1");

    // ---- Identity ----
    writeKeychainValue(@"auth_email_secure",    @"activated@ytk.local");
    writeKeychainValue(@"auth_license_secure",  kFakeLicense);
    writeKeychainValue(@"auth_device_secure",   @"YTKHelper");
    writeKeychainValue(@"auth_expires_secure",  @"01-01-2030 12:00 AM");
    writeKeychainValue(@"auth_session_token",   @"YTKHelper-Token");
    writeKeychainValue(@"auth_timestamp",       @"9999999999");

    // ---- 5.6.1 gate keys: skip activation/stats POSTs ----
    writeKeychainValue(@"activation_logged_for_key", kFakeLicense);
    writeKeychainValue(@"lastStatsReportedVersion",  kYTKVersion);

    // ---- Empty banlists (defense in depth in case verifier passes anyway) ----
    writeKeychainValue(@"ytk_rc_cache",            @"{\"bannedUUIDs\":[],\"bannedDylibs\":[]}");
    writeKeychainValue(@"ytk_banned_uuids",        @"[]");
    writeKeychainValue(@"ytk_banned_dylib_names",  @"[]");

    // ---- Force-fail the seal verifier (banlist refetch) ----
    // FUN_3cbb8 logic: verifier returning 0 → XOR mismatch → SKIP refetch
    writeKeychainValue(@"ytk_last_contact_ts",   kFutureTs);
    writeKeychainValue(@"ytk_last_contact_seal", kJunkSeal);

    // ---- Force-fail the seal verifier (activation refetch) ----
    // Same FUN_472dc pattern at line 38933 → same buggy gate
    writeKeychainValue(@"auth_last_verified_ts",   kFutureTs);
    writeKeychainValue(@"auth_last_verified_seal", kJunkSeal);

    // ---- Clear integrity seal (no last-known-good for verifier to compare) ----
    writeKeychainValue(@"auth_integrity_seal", nil);

    LOG(@"Keychain pre-seeded (v2.1: junk seals + empty banlists)");
}

// ============================================================
#pragma mark — Constructor
// ============================================================
__attribute__((constructor))
static void init(void) {
    preseedKeychain();
    LOG(@"YTKHelper v2.1 loaded — exploiting seal verifier XOR bug");

    // First-launch: write keychain, then exit so YTK reads preseeded values next time
    NSString *flagKey = @"com.itzzace.ytkhelper.firstLaunchDone.v21";
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
