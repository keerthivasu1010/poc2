/**
 * @file transaction.c
 * @brief UPI-style fund transfer: validation, AES-128 encryption,
 *        SHA-256 integrity hashing, and persistence (DIGI-6..DIGI-9).
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "transaction.h"
#include "storage.h"
#include "aes.h"
#include "integrity.h"
#include "audit.h"

/**
 * Platform-wide AES-128 key used to encrypt transaction payloads at
 * rest. In a production deployment this would be sourced from a
 * hardware security module or KMS rather than embedded in source.
 */
static const uint8_t PLATFORM_AES_KEY[AES_KEY_SIZE] = {
    0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
    0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
};

static void make_timestamp(char *buf, size_t bufSize)
{
    time_t now = time(NULL);
    struct tm tmBuf;
    /* localtime_r() rather than localtime(): this function can now
     * run on multiple threads concurrently (see
     * bank_process_transfers_concurrently()), and plain localtime()
     * is not thread-safe (shared static return buffer). */
    const struct tm *tmInfo = localtime_r(&now, &tmBuf);
    if (tmInfo != NULL)
    {
        (void)strftime(buf, bufSize, "%Y-%m-%d %H:%M:%S", tmInfo);
    }
    else
    {
        strncpy(buf, "unknown", bufSize - 1U);
        buf[bufSize - 1U] = '\0';
    }
}

int upi_is_valid_format(const char *upiId)
{
    size_t len;
    size_t i;
    size_t atPos = 0;
    size_t atCount = 0;

    if (upiId == NULL)
    {
        return 0;
    }

    len = strlen(upiId);
    if ((len < 3U) || (len >= (size_t)MAX_UPI_LEN))
    {
        return 0;
    }

    for (i = 0U; i < len; i++)
    {
        unsigned char c = (unsigned char)upiId[i];

        if (c == '@')
        {
            atCount++;
            atPos = i;
        }
        else if ((isalnum(c) == 0) && (c != '.') && (c != '-') && (c != '_'))
        {
            return 0;
        }
    }

    if (atCount != 1U)
    {
        return 0;
    }

    if ((atPos == 0U) || (atPos == (len - 1U)))
    {
        return 0;
    }

    return 1;
}

/**
 * Original single-threaded transfer logic, unchanged. Made static
 * and renamed to *_impl: the whole sequence below is a classic
 * "read balance, decide, then write balance" critical section, so
 * the public transaction_transfer() wrapper (below) now runs it
 * under storage_lock()/storage_unlock() to make it atomic across
 * threads, instead of scattering lock calls through every return
 * path here.
 */
static int transaction_transfer_impl(const char *sender, const char *receiverUpi, double amount)
{
    User senderUser;
    User receiverUser;
    int  receiverIsLocal;
    Transaction txn;
    char payload[MAX_LINE_LEN];
    char timestamp[MAX_TIMESTAMP_LEN];
    const char *receiverLabel;

    if ((sender == NULL) || (receiverUpi == NULL) || (amount <= 0.0))
    {
        return -1;
    }

    if (upi_is_valid_format(receiverUpi) != 1)
    {
        (void)audit_log(sender, "transfer failed: malformed UPI ID");
        return -6;
    }

    if (storage_find_user(sender, &senderUser) != 1)
    {
        (void)audit_log(sender, "transfer failed: sender not found");
        return -2;
    }

    if (strcmp(senderUser.upiID, receiverUpi) == 0)
    {
        (void)audit_log(sender, "transfer failed: cannot transfer to self");
        return -1;
    }

    /*
     * The receiver's UPI ID does not need to belong to a user
     * registered on this platform -- just like real UPI, a payment
     * can be sent to any syntactically valid UPI ID at any bank/PSP.
     * If it happens to resolve to a local account, we credit that
     * account's balance directly; otherwise the transfer is recorded
     * as an outbound payment to an external UPI handle and only the
     * sender's balance is debited.
     */
    receiverIsLocal = (storage_find_user_by_upi(receiverUpi, &receiverUser) == 1) ? 1 : 0;
    receiverLabel = receiverIsLocal ? receiverUser.username : receiverUpi;

    if (senderUser.balance < amount)
    {
        (void)audit_log(sender, "transfer failed: insufficient balance");
        return -4;
    }

    make_timestamp(timestamp, sizeof(timestamp));

    (void)snprintf(payload, sizeof(payload), "%s|%s|%.2f|%s",
                    sender, receiverUpi, amount, timestamp);

    if (aes128_encrypt_to_hex(payload, PLATFORM_AES_KEY,
                               txn.encryptedData, sizeof(txn.encryptedData)) != 0)
    {
        (void)audit_log(sender, "transfer failed: encryption error");
        return -5;
    }

    if (integrity_compute_hash(sender, receiverUpi, amount, timestamp, txn.hash) != 0)
    {
        (void)audit_log(sender, "transfer failed: hashing error");
        return -5;
    }

    strncpy(txn.sender, sender, sizeof(txn.sender) - 1U);
    txn.sender[sizeof(txn.sender) - 1U] = '\0';
    strncpy(txn.receiver, receiverUpi, sizeof(txn.receiver) - 1U);
    txn.receiver[sizeof(txn.receiver) - 1U] = '\0';
    txn.amount = amount;
    strncpy(txn.timestamp, timestamp, sizeof(txn.timestamp) - 1U);
    txn.timestamp[sizeof(txn.timestamp) - 1U] = '\0';

    if (storage_update_balance(sender, senderUser.balance - amount) != 0)
    {
        (void)audit_log(sender, "transfer failed: could not debit sender");
        return -5;
    }

    if (receiverIsLocal == 1)
    {
        if (storage_update_balance(receiverUser.username, receiverUser.balance + amount) != 0)
        {
            /* Attempt to roll back the debit to avoid losing funds. */
            (void)storage_update_balance(sender, senderUser.balance);
            (void)audit_log(sender, "transfer failed: could not credit receiver, rolled back");
            return -5;
        }
    }

    if (storage_add_transaction(&txn) != 0)
    {
        (void)audit_log(sender, "transfer warning: funds moved but transaction log write failed");
        return -5;
    }

    printf("Transfer successful: %.2f from %s to %s at %s\n",
           amount, sender, receiverUpi, timestamp);

    {
        char logMsg[128];
        (void)snprintf(logMsg, sizeof(logMsg), "transfer of %.2f to %s", amount, receiverUpi);
        (void)audit_log(sender, logMsg);
        if (receiverIsLocal == 1)
        {
            (void)snprintf(logMsg, sizeof(logMsg), "received %.2f from %s", amount, sender);
            (void)audit_log(receiverLabel, logMsg);
        }
    }

    return 0;
}

int transaction_transfer(const char *sender, const char *receiverUpi, double amount)
{
    int result;

    /*
     * Hold the storage lock for the entire transfer so that two
     * threads transferring funds concurrently (including to/from
     * the same account) can never interleave between reading a
     * balance and writing the updated balance -- which would
     * otherwise be able to lose an update or allow an overdraft
     * past the balance check.
     */
    storage_lock();
    result = transaction_transfer_impl(sender, receiverUpi, amount);
    storage_unlock();

    return result;
}
