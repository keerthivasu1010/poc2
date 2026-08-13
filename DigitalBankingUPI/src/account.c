/**
 * @file account.c
 * @brief Self-service account management: change password/PIN and
 *        deposit funds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "account.h"
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

static int is_valid_password(const char *password)
{
    size_t len;
    if (password == NULL)
    {
        return 0;
    }
    len = strlen(password);
    return ((len >= 6U) && (len < MAX_PASSWORD_LEN)) ? 1 : 0;
}

static int is_valid_pin(const char *pin)
{
    size_t len;
    size_t i;

    if (pin == NULL)
    {
        return 0;
    }
    len = strlen(pin);
    if ((len != 4U) && (len != 6U))
    {
        return 0;
    }
    for (i = 0U; i < len; ++i)
    {
        if (isdigit((unsigned char)pin[i]) == 0)
        {
            return 0;
        }
    }
    return 1;
}

/**
 * Original implementation, unchanged, renamed to *_impl. The public
 * account_change_credentials() wrapper below runs this whole
 * read-verify-write sequence under storage_lock()/storage_unlock()
 * so that (for example) two threads can't both read the same stale
 * balance/credential record and then both write, silently losing
 * one of the updates.
 */
static int account_change_credentials_impl(Session *session)
{
    char currentPassword[MAX_PASSWORD_LEN];
    char currentPin[MAX_PIN_LEN];
    char currentCredential[MAX_PASSWORD_LEN + MAX_PIN_LEN];
    char currentHash[65];
    char newPassword[MAX_PASSWORD_LEN];
    char newPin[MAX_PIN_LEN];
    char newCredential[MAX_PASSWORD_LEN + MAX_PIN_LEN];
    User user;

    if ((session == NULL) || (session->isLoggedIn == 0))
    {
        return -1;
    }

    printf("\n--- Change Password / PIN ---\n");

    if (storage_find_user(session->currentUser.username, &user) != 1)
    {
        printf("Could not load account.\n");
        return -1;
    }

    printf("Enter current password: ");
    if (read_line(currentPassword, sizeof(currentPassword)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    printf("Enter current PIN: ");
    if (read_line(currentPin, sizeof(currentPin)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }

    (void)snprintf(currentCredential, sizeof(currentCredential), "%s:%s",
                    currentPassword, currentPin);
    memset(currentPassword, 0, sizeof(currentPassword));
    memset(currentPin, 0, sizeof(currentPin));

    if (sha256_hash_string(currentCredential, currentHash) != 0)
    {
        memset(currentCredential, 0, sizeof(currentCredential));
        printf("Internal hashing error.\n");
        return -1;
    }
    memset(currentCredential, 0, sizeof(currentCredential));

    if (strcmp(currentHash, user.passwordHash) != 0)
    {
        printf("Current password/PIN is incorrect. No changes made.\n");
        (void)audit_log(user.username, "change credentials failed: bad current credentials");
        return -1;
    }

    printf("Enter new password (min 6 chars): ");
    if (read_line(newPassword, sizeof(newPassword)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    if (is_valid_password(newPassword) == 0)
    {
        printf("Invalid new password.\n");
        memset(newPassword, 0, sizeof(newPassword));
        return -1;
    }

    printf("Enter new PIN (4 or 6 digits): ");
    if (read_line(newPin, sizeof(newPin)) != 0)
    {
        printf("Input error.\n");
        memset(newPassword, 0, sizeof(newPassword));
        return -1;
    }
    if (is_valid_pin(newPin) == 0)
    {
        printf("Invalid new PIN.\n");
        memset(newPassword, 0, sizeof(newPassword));
        memset(newPin, 0, sizeof(newPin));
        return -1;
    }

    (void)snprintf(newCredential, sizeof(newCredential), "%s:%s", newPassword, newPin);
    memset(newPassword, 0, sizeof(newPassword));
    memset(newPin, 0, sizeof(newPin));

    if (sha256_hash_string(newCredential, user.passwordHash) != 0)
    {
        memset(newCredential, 0, sizeof(newCredential));
        printf("Internal hashing error.\n");
        return -1;
    }
    memset(newCredential, 0, sizeof(newCredential));

    if (storage_update_user(&user) != 0)
    {
        printf("Failed to persist new credentials.\n");
        (void)audit_log(user.username, "change credentials failed: storage error");
        return -1;
    }

    session->currentUser = user;

    printf("Password/PIN updated successfully.\n");
    (void)audit_log(user.username, "password/PIN changed");

    return 0;
}

int account_change_credentials(Session *session)
{
    int result;

    storage_lock();
    result = account_change_credentials_impl(session);
    storage_unlock();

    return result;
}

/**
 * Original implementation, unchanged, renamed to *_impl -- see the
 * comment above account_change_credentials_impl() for why the
 * public wrapper below takes the storage lock for the whole
 * operation (read balance, add deposit, write balance).
 */
static int account_deposit_funds_impl(Session *session)
{
    char amountStr[32];
    double amount;
    User user;
    char logMsg[96];

    if ((session == NULL) || (session->isLoggedIn == 0))
    {
        return -1;
    }

    printf("\n--- Deposit Funds ---\n");
    printf("Amount to deposit: ");
    if (read_line(amountStr, sizeof(amountStr)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    amount = atof(amountStr);

    if (amount <= 0.0)
    {
        printf("Deposit amount must be positive.\n");
        return -1;
    }

    if (storage_find_user(session->currentUser.username, &user) != 1)
    {
        printf("Could not load account.\n");
        return -1;
    }

    user.balance += amount;

    if (storage_update_user(&user) != 0)
    {
        printf("Deposit failed due to a storage error.\n");
        (void)audit_log(user.username, "deposit failed: storage error");
        return -1;
    }

    session->currentUser = user;

    printf("Deposit successful. New balance: %.2f\n", user.balance);
    (void)snprintf(logMsg, sizeof(logMsg), "deposited %.2f, new balance %.2f", amount, user.balance);
    (void)audit_log(user.username, logMsg);

    return 0;
}

int account_deposit_funds(Session *session)
{
    int result;

    storage_lock();
    result = account_deposit_funds_impl(session);
    storage_unlock();

    return result;
}
