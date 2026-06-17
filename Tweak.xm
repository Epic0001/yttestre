/*
 *  YTKHelper reset build ? clears known YTKPlus keychain state, logs, exits.
 *  Install/run once, then reinstall the normal build for clean-device testing.
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

#define LOG(fmt, ...) NSLog(@"[YTKReset] " fmt, ##__VA_ARGS__)

static NSString *const kService = @"me.ikghd.ytkplus.secure";

static NSString *resetLogPath(void) {
    return [NSTemporaryDirectory() stringByAppendingPathComponent:@"YTKHelper-reset.log"];
}

static void resetLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    LOG(@"%@", msg);
    NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    NSString *path = resetLogPath();
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) [data writeToFile:path atomically:YES];
    else { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
}

static OSStatus deleteAccount(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kService,
        (__bridge id)kSecAttrAccount: account,
    };
    OSStatus st = SecItemDelete((__bridge CFDictionaryRef)query);
    resetLog(@"delete %@ status=%d", account, (int)st);
    return st;
}

__attribute__((constructor))
static void init(void) {
    [[NSFileManager defaultManager] removeItemAtPath:resetLogPath() error:nil];
    resetLog(@"YTKHelper reset build started");

    NSArray<NSString *> *keys = @[
        @"Etmvdvihq chmhc rml",
        @"Enabledytk_status",
        @"auth_status_secure",
        @"activation_logged",
        @"stats_sent_before",
        @"auth_email_secure",
        @"auth_license_secure",
        @"auth_device_secure",
        @"auth_expires_secure",
        @"auth_session_token",
        @"auth_timestamp",
        @"activation_logged_for_key",
        @"lastStatsReportedVersion",
        @"ytk_rc_cache",
        @"ytk_banned_uuids",
        @"ytk_banned_dylib_names",
        @"ytk_last_contact_ts",
        @"ytk_last_contact_seal",
        @"auth_last_verified_ts",
        @"auth_last_verified_seal",
        @"auth_integrity_seal",
        @"auth_last_verified_seal",
        @"auth_last_verified_ts",
        @"ytk_last_contact_seal",
        @"ytk_last_contact_ts",
        @"auth_device_id_secure",
        @"auth_status",
        @"auth_license",
        @"auth_email",
        @"license_key",
        @"lastStatsReportedVersion",
        @"ytk_banned_dylib_names"
    ];

    int ok = 0, missing = 0, other = 0;
    for (NSString *key in keys) {
        OSStatus st = deleteAccount(key);
        if (st == errSecSuccess) ok++;
        else if (st == errSecItemNotFound) missing++;
        else other++;
    }
    resetLog(@"summary success=%d missing=%d other=%d", ok, missing, other);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        resetLog(@"exiting after reset");
        exit(0);
    });
}
