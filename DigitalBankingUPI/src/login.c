/**
 * @file login.c
 * @brief Interactive user login / authentication flow (DIGI-2, DIGI-20, DIGI-22).
 *
 * Also implements brute-force lockout: after MAX_FAILED_LOGIN_ATTEMPTS
 * consecutive bad logins for an account, that account is locked for
 * LOCKOUT_DURATION_SECONDS (or until an administrator clears the
 * lock). Frozen accounts (set via the admin panel) are refused login
 * entirely regardless of credentials.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "auth.h"
#include "sha256.h"
#include "storage.h"
#include "audit.h"

#define MAX_PASSWORD_LEN 64
#define MAX_PIN_LEN      8

static int read_line(char *buf, size_t bufSize)
{
    size_t len;

    if (fgets(buf, (int)bufSize, stdin) == NULL)
    {
        return -1;
    }

    len = strlen(buf);

    /* If the buffer was filled exactly and the last character read
     * is not a newline, the input line was longer than the buffer
     * (or exactly filled it, leaving the newline unread). Drain the
     * remainder of the line so it cannot leak into the next prompt
     * as spurious input. */
    if ((len == (bufSize - 1U)) && (buf[len - 1U] != '\n'))
    {
        int c;
        do
        {
            c = getchar();
        } while ((c != '\n') && (c != EOF));
    }

    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}

static void register_failed_attempt(User *user)
{
    user->failedAttempts++;

    if (user->failedAttempts >= MAX_FAILED_LOGIN_ATTEMPTS)
    {
        user->lockedUntilEpoch = (long)time(NULL) + LOCKOUT_DURATION_SECONDS;
        printf("Too many failed attempts. Account locked for %ld seconds.\n",
               LOCKOUT_DURATION_SECONDS);
        (void)audit_log(user->username, "account locked: too many failed login attempts");
    }

    (void)storage_update_user(user);
}

/**
 * Original implementation, unchanged, renamed to *_impl. Login reads
 * a user's lockout/attempt counters, decides whether to allow the
 * attempt, and then writes updated counters back -- another
 * check-then-act sequence -- so the public login_authenticate()
 * wrapper below runs the whole thing under storage_lock()/
 * storage_unlock() to keep two concurrent login attempts for the
 * same account from racing on the failed-attempt counter or the
 * lockout timestamp.
 */
static int login_authenticate_impl(Session *outSession)
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char pin[MAX_PIN_LEN];
    char credential[MAX_PASSWORD_LEN + MAX_PIN_LEN];
    char computedHash[65];
    User user;
    int found;
    long now;

    if (outSession == NULL)
    {
        return -1;
    }

    printf("\n--- User Login ---\n");

    printf("Username: ");
    if (read_line(username, sizeof(username)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }

    printf("Password: ");
    if (read_line(password, sizeof(password)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }

    printf("PIN: ");
    if (read_line(pin, sizeof(pin)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }

    found = storage_find_user(username, &user);
    if (found != 1)
    {
        printf("Invalid username or password.\n");
        (void)audit_log(username, "login failed: user not found");
        memset(password, 0, sizeof(password));
        memset(pin, 0, sizeof(pin));
        return -1;
    }

    if (user.isFrozen != 0)
    {
        printf("This account has been frozen by an administrator.\n");
        (void)audit_log(username, "login failed: account frozen");
        memset(password, 0, sizeof(password));
        memset(pin, 0, sizeof(pin));
        return -1;
    }

    now = (long)time(NULL);
    if ((user.lockedUntilEpoch > 0L) && (now < user.lockedUntilEpoch))
    {
        printf("Account is locked due to repeated failed logins. Try again in %ld second(s).\n",
               user.lockedUntilEpoch - now);
        (void)audit_log(username, "login failed: account locked");
        memset(password, 0, sizeof(password));
        memset(pin, 0, sizeof(pin));
        return -1;
    }
    if ((user.lockedUntilEpoch > 0L) && (now >= user.lockedUntilEpoch))
    {
        /* Lockout period has expired; clear it before continuing. */
        user.lockedUntilEpoch = 0L;
        user.failedAttempts = 0;
        (void)storage_update_user(&user);
    }

    (void)snprintf(credential, sizeof(credential), "%s:%s", password, pin);
    if (sha256_hash_string(credential, computedHash) != 0)
    {
        printf("Internal hashing error.\n");
        return -1;
    }

    memset(password, 0, sizeof(password));
    memset(pin, 0, sizeof(pin));
    memset(credential, 0, sizeof(credential));

    if (strcmp(computedHash, user.passwordHash) != 0)
    {
        printf("Invalid username or password.\n");
        (void)audit_log(username, "login failed: bad credentials");
        register_failed_attempt(&user);
        return -1;
    }

    if (user.failedAttempts != 0 || user.lockedUntilEpoch != 0)
    {
        user.failedAttempts = 0;
        user.lockedUntilEpoch = 0L;
        (void)storage_update_user(&user);
    }

    outSession->isLoggedIn = 1;
    outSession->currentUser = user;

    printf("Login successful. Welcome, %s!\n", user.username);
    (void)audit_log(username, "login successful");

    return 0;
}

int login_authenticate(Session *outSession)
{
    int result;

    storage_lock();
    result = login_authenticate_impl(outSession);
    storage_unlock();

    return result;
}
