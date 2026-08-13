/**
 * @file history.c
 * @brief Transaction history display for a given user.
 */

#include <stdio.h>
#include <string.h>
#include "transaction.h"
#include "storage.h"
#include "aes.h"

/* Must match the key used in transaction.c to encrypt payloads. */
static const uint8_t PLATFORM_AES_KEY[AES_KEY_SIZE] = {
    0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
    0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
};

typedef struct
{
    const char *username;
    int         count;
} HistoryContext;

static void history_visitor(const Transaction *txn, void *userData)
{
    HistoryContext *ctx = (HistoryContext *)userData;
    char decrypted[MAX_LINE_LEN];

    if ((strcmp(txn->sender, ctx->username) != 0) &&
        (strcmp(txn->receiver, ctx->username) != 0))
    {
        return;
    }

    ctx->count++;

    if (aes128_decrypt_from_hex(txn->encryptedData, PLATFORM_AES_KEY,
                                 decrypted, sizeof(decrypted)) != 0)
    {
        printf("%2d) [DECRYPTION ERROR] %s -> %s : %.2f at %s\n",
               ctx->count, txn->sender, txn->receiver, txn->amount, txn->timestamp);
        return;
    }

    printf("%2d) %s -> %s : %.2f at %s\n",
           ctx->count, txn->sender, txn->receiver, txn->amount, txn->timestamp);
    printf("     decrypted payload: %s\n", decrypted);
}

int transaction_show_history(const char *username)
{
    HistoryContext ctx;
    int visited;

    if (username == NULL)
    {
        return -1;
    }

    ctx.username = username;
    ctx.count = 0;

    printf("\n--- Transaction History for %s ---\n", username);

    visited = storage_for_each_transaction(history_visitor, &ctx);
    if (visited < 0)
    {
        printf("Could not read transaction store.\n");
        return -1;
    }

    if (ctx.count == 0)
    {
        printf("No transactions found.\n");
    }

    return ctx.count;
}
