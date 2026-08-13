/**
 * @file bank.h
 * @brief Core data structures and shared definitions for the Digital
 *        Banking & UPI Transaction Security Platform.
 */

#ifndef BANK_H
#define BANK_H

#include <stdint.h>

#define MAX_USERNAME_LEN   30
/* Must be large enough to hold the longest possible generated UPI ID
 * ("<username up to MAX_USERNAME_LEN-1 chars>@digitalbank" plus the
 * terminating NUL) with headroom for other PSP suffixes
 * (e.g. "@okhdfcbank", "@ybl", "@paytm"). This avoids
 * -Wformat-truncation on the snprintf() that builds upiID. */
#define MAX_UPI_LEN        48
#define MAX_LINE_LEN       512
#define USERS_DB_PATH      "database/users.dat"
#define TRANSACTIONS_DB_PATH "database/transactions.dat"
#define AUDIT_LOG_PATH     "database/audit.log"

/** Number of consecutive failed login attempts before an account is
 *  automatically locked out. */
#define MAX_FAILED_LOGIN_ATTEMPTS 5

/** Duration (seconds) an account stays locked after too many failed
 *  login attempts. */
#define LOCKOUT_DURATION_SECONDS  300L

/** Default bootstrap administrator credentials, created automatically
 *  on first run if no admin account exists yet. The password should
 *  be changed immediately via the "Change Password/PIN" feature in a
 *  real deployment. */
#define DEFAULT_ADMIN_USERNAME "admin"
#define DEFAULT_ADMIN_PASSWORD "Admin@123"
#define DEFAULT_ADMIN_PIN      "000000"

/**
 * @brief Represents a registered banking user.
 *
 * passwordHash holds the hex-encoded SHA-256 digest of the user's
 * password concatenated with their PIN; the raw credential is never
 * persisted.
 *
 * failedAttempts and lockedUntilEpoch implement a simple brute-force
 * lockout: after MAX_FAILED_LOGIN_ATTEMPTS consecutive bad logins,
 * lockedUntilEpoch is set to (now + LOCKOUT_DURATION_SECONDS) and
 * login is refused until that time has passed or an administrator
 * clears the lock.
 */
typedef struct
{
    char   username[MAX_USERNAME_LEN];
    char   passwordHash[65];
    char   upiID[MAX_UPI_LEN];
    double balance;
    int    isAdmin;
    int    isFrozen;
    int    failedAttempts;
    long   lockedUntilEpoch;
} User;

/**
 * @brief Session information for the currently authenticated user.
 */
typedef struct
{
    int  isLoggedIn;
    User currentUser;
} Session;

#endif /* BANK_H */
