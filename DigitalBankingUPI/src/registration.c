/**
 * @file registration.c
 * @brief Interactive user registration flow (DIGI-1, DIGI-3, DIGI-16).
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "auth.h"
#include "sha256.h"
#include "storage.h"
#include "audit.h"

#define MAX_PASSWORD_LEN 64
#define MAX_PIN_LEN      8
#define STARTING_BALANCE 1000.00

/**
 * @brief Read a line from stdin safely, stripping the trailing
 *        newline, using fgets() to avoid buffer overflow.
 */
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

static int is_valid_username(const char *username)
{
    size_t len;
    size_t i;

    if (username == NULL)
    {
        return 0;
    }
    len = strlen(username);
    if ((len < 3U) || (len >= MAX_USERNAME_LEN))
    {
        return 0;
    }
    for (i = 0U; i < len; ++i)
    {
        if (!(isalnum((unsigned char)username[i]) || (username[i] == '_')))
        {
            return 0;
        }
    }
    return 1;
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

int registration_register(void)
{
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char pin[MAX_PIN_LEN];
    char credential[MAX_PASSWORD_LEN + MAX_PIN_LEN];
    User newUser;

    memset(&newUser, 0, sizeof(newUser));

    printf("\n--- User Registration ---\n");

    printf("Enter username (3-29 alphanumeric/underscore chars): ");
    if (read_line(username, sizeof(username)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    if (is_valid_username(username) == 0)
    {
        printf("Invalid username.\n");
        (void)audit_log("SYSTEM", "registration failed: invalid username");
        return -1;
    }

    {
        User existing;
        if (storage_find_user(username, &existing) == 1)
        {
            printf("Username already exists.\n");
            (void)audit_log(username, "registration failed: duplicate username");
            return -1;
        }
    }

    printf("Enter password (min 6 chars): ");
    if (read_line(password, sizeof(password)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    if (is_valid_password(password) == 0)
    {
        printf("Invalid password.\n");
        (void)audit_log(username, "registration failed: invalid password");
        return -1;
    }

    printf("Enter PIN (4 or 6 digits): ");
    if (read_line(pin, sizeof(pin)) != 0)
    {
        printf("Input error.\n");
        return -1;
    }
    if (is_valid_pin(pin) == 0)
    {
        printf("Invalid PIN.\n");
        (void)audit_log(username, "registration failed: invalid PIN");
        return -1;
    }

    (void)snprintf(credential, sizeof(credential), "%s:%s", password, pin);

    if (sha256_hash_string(credential, newUser.passwordHash) != 0)
    {
        printf("Internal hashing error.\n");
        return -1;
    }

    /* Clear sensitive plaintext buffers as soon as they are no
     * longer needed. */
    memset(password, 0, sizeof(password));
    memset(pin, 0, sizeof(pin));
    memset(credential, 0, sizeof(credential));

    strncpy(newUser.username, username, sizeof(newUser.username) - 1U);
    newUser.username[sizeof(newUser.username) - 1U] = '\0';

    (void)snprintf(newUser.upiID, sizeof(newUser.upiID), "%s@digitalbank", username);
    newUser.balance = STARTING_BALANCE;

    if (storage_add_user(&newUser) != 0)
    {
        printf("Registration failed: could not persist user.\n");
        (void)audit_log(username, "registration failed: storage error");
        return -1;
    }

    printf("Registration successful. Your UPI ID is %s\n", newUser.upiID);
    printf("Starting balance: %.2f\n", newUser.balance);
    (void)audit_log(username, "registration successful");

    return 0;
}
