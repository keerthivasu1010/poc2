/**
 * @file integrity.c
 * @brief Transaction integrity verification (DIGI-9).
 */

#include <stdio.h>
#include <string.h>
#include "integrity.h"
#include "storage.h"
#include "sha256.h"
#include "audit.h"

int integrity_compute_hash(const char *sender,
                            const char *receiver,
                            double      amount,
                            const char *timestamp,
                            char        outHash[65])
{
    char payload[MAX_LINE_LEN];

    if ((sender == NULL) || (receiver == NULL) || (timestamp == NULL) || (outHash == NULL))
    {
        return -1;
    }

    (void)snprintf(payload, sizeof(payload), "%s|%s|%.2f|%s",
                    sender, receiver, amount, timestamp);

    return sha256_hash_string(payload, outHash);
}

typedef struct
{
    const char *username;
    int         checked;
    int         verifiedCount;
    int         tamperedCount;
} VerifyContext;

static void verify_visitor(const Transaction *txn, void *userData)
{
    VerifyContext *ctx = (VerifyContext *)userData;
    char recomputed[65];

    if ((strcmp(txn->sender, ctx->username) != 0) &&
        (strcmp(txn->receiver, ctx->username) != 0))
    {
        return;
    }

    ctx->checked++;

    if (integrity_compute_hash(txn->sender, txn->receiver, txn->amount,
                                txn->timestamp, recomputed) != 0)
    {
        printf("  [ERROR] Could not recompute hash for transaction at %s\n", txn->timestamp);
        return;
    }

    if (strcmp(recomputed, txn->hash) == 0)
    {
        printf("  [VERIFIED] %s -> %s : %.2f at %s\n",
               txn->sender, txn->receiver, txn->amount, txn->timestamp);
        ctx->verifiedCount++;
    }
    else
    {
        printf("  [TAMPERED] %s -> %s : %.2f at %s\n",
               txn->sender, txn->receiver, txn->amount, txn->timestamp);
        ctx->tamperedCount++;
    }
}

int integrity_verify_user_transactions(const char *username)
{
    VerifyContext ctx;
    int visited;
    char logMsg[128];

    if (username == NULL)
    {
        return -1;
    }

    ctx.username = username;
    ctx.checked = 0;
    ctx.verifiedCount = 0;
    ctx.tamperedCount = 0;

    printf("\n--- Transaction Integrity Verification ---\n");

    visited = storage_for_each_transaction(verify_visitor, &ctx);
    if (visited < 0)
    {
        printf("Could not read transaction store.\n");
        return -1;
    }

    if (ctx.checked == 0)
    {
        printf("No transactions found for this account.\n");
    }
    else
    {
        printf("Checked %d transaction(s): %d verified, %d tampered.\n",
               ctx.checked, ctx.verifiedCount, ctx.tamperedCount);
    }

    (void)snprintf(logMsg, sizeof(logMsg),
                    "integrity check: %d checked, %d verified, %d tampered",
                    ctx.checked, ctx.verifiedCount, ctx.tamperedCount);
    (void)audit_log(username, logMsg);

    return ctx.checked;
}
