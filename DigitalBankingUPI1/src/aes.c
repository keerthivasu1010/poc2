/**
 * @file aes.c
 * @brief AES-128 block cipher implementation (FIPS PUB 197), used in
 *        ECB mode with PKCS#7 padding for encrypting transaction
 *        payloads before persistence.
 */

#include <string.h>
#include <stdio.h>
#include "aes.h"

/* Internal scratch buffer size for hex convenience wrappers; large
 * enough for the transaction payload strings used by this platform. */
#define MAX_ENCRYPTED_LEN_INTERNAL 256U

#define AES_ROUNDS   10U
#define AES_NB       4U
#define AES_NK       4U

typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[11] = {
    0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

/* Expanded round key schedule: 4*(rounds+1) words of 4 bytes each */
typedef uint8_t roundkey_t[176];

static void key_expansion(const uint8_t key[AES_KEY_SIZE], roundkey_t rk)
{
    uint8_t tempa[4];
    uint32_t i;

    for (i = 0U; i < AES_NK; ++i)
    {
        rk[i * 4U + 0U] = key[i * 4U + 0U];
        rk[i * 4U + 1U] = key[i * 4U + 1U];
        rk[i * 4U + 2U] = key[i * 4U + 2U];
        rk[i * 4U + 3U] = key[i * 4U + 3U];
    }

    for (i = AES_NK; i < AES_NB * (AES_ROUNDS + 1U); ++i)
    {
        tempa[0] = rk[(i - 1U) * 4U + 0U];
        tempa[1] = rk[(i - 1U) * 4U + 1U];
        tempa[2] = rk[(i - 1U) * 4U + 2U];
        tempa[3] = rk[(i - 1U) * 4U + 3U];

        if ((i % AES_NK) == 0U)
        {
            uint8_t t = tempa[0];
            tempa[0] = sbox[tempa[1]] ^ rcon[i / AES_NK];
            tempa[1] = sbox[tempa[2]];
            tempa[2] = sbox[tempa[3]];
            tempa[3] = sbox[t];
        }

        rk[i * 4U + 0U] = rk[(i - AES_NK) * 4U + 0U] ^ tempa[0];
        rk[i * 4U + 1U] = rk[(i - AES_NK) * 4U + 1U] ^ tempa[1];
        rk[i * 4U + 2U] = rk[(i - AES_NK) * 4U + 2U] ^ tempa[2];
        rk[i * 4U + 3U] = rk[(i - AES_NK) * 4U + 3U] ^ tempa[3];
    }
}

/* state is indexed as state[row][col]. Each round-key word (4 bytes)
 * corresponds to one column, so byte (row, col) of round `round`
 * lives at rk[round*16 + col*4 + row]. */
static void add_round_key(uint8_t round, state_t *state, const roundkey_t rk)
{
    uint8_t row, col;
    for (row = 0U; row < 4U; ++row)
    {
        for (col = 0U; col < 4U; ++col)
        {
            (*state)[row][col] ^= rk[(round * AES_NB * 4U) + (col * 4U) + row];
        }
    }
}

static void sub_bytes(state_t *state)
{
    uint8_t i, j;
    for (i = 0U; i < 4U; ++i)
    {
        for (j = 0U; j < 4U; ++j)
        {
            (*state)[i][j] = sbox[(*state)[i][j]];
        }
    }
}

static void inv_sub_bytes(state_t *state)
{
    uint8_t i, j;
    for (i = 0U; i < 4U; ++i)
    {
        for (j = 0U; j < 4U; ++j)
        {
            (*state)[i][j] = rsbox[(*state)[i][j]];
        }
    }
}

/* Row r is cyclically shifted left by r positions across the 4
 * columns. Row 0 is untouched. */
static void shift_rows(state_t *state)
{
    uint8_t row;
    for (row = 1U; row < 4U; ++row)
    {
        uint8_t tmp[4];
        uint8_t col;
        for (col = 0U; col < 4U; ++col)
        {
            tmp[col] = (*state)[row][(col + row) % 4U];
        }
        for (col = 0U; col < 4U; ++col)
        {
            (*state)[row][col] = tmp[col];
        }
    }
}

/* Inverse: row r is cyclically shifted right by r positions. */
static void inv_shift_rows(state_t *state)
{
    uint8_t row;
    for (row = 1U; row < 4U; ++row)
    {
        uint8_t tmp[4];
        uint8_t col;
        for (col = 0U; col < 4U; ++col)
        {
            tmp[(col + row) % 4U] = (*state)[row][col];
        }
        for (col = 0U; col < 4U; ++col)
        {
            (*state)[row][col] = tmp[col];
        }
    }
}

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1U) ? 0x1bU : 0x00U));
}

static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0U;
    uint8_t counter;

    for (counter = 0U; counter < 8U; ++counter)
    {
        uint8_t hi_bit_set;

        if ((b & 1U) != 0U)
        {
            p ^= a;
        }
        hi_bit_set = (uint8_t)(a & 0x80U);
        a <<= 1;
        if (hi_bit_set != 0U)
        {
            a ^= 0x1bU;
        }
        b >>= 1;
    }
    return p;
}

static void mix_columns(state_t *state)
{
    uint8_t i;

    for (i = 0U; i < 4U; ++i)
    {
        uint8_t a0, a1, a2, a3;
        a0 = (*state)[0][i]; a1 = (*state)[1][i]; a2 = (*state)[2][i]; a3 = (*state)[3][i];

        (*state)[0][i] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        (*state)[1][i] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        (*state)[2][i] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        (*state)[3][i] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void inv_mix_columns(state_t *state)
{
    uint8_t i;

    for (i = 0U; i < 4U; ++i)
    {
        uint8_t a0, a1, a2, a3;
        a0 = (*state)[0][i]; a1 = (*state)[1][i]; a2 = (*state)[2][i]; a3 = (*state)[3][i];

        (*state)[0][i] = (uint8_t)(gmul(a0, 0x0eU) ^ gmul(a1, 0x0bU) ^ gmul(a2, 0x0dU) ^ gmul(a3, 0x09U));
        (*state)[1][i] = (uint8_t)(gmul(a0, 0x09U) ^ gmul(a1, 0x0eU) ^ gmul(a2, 0x0bU) ^ gmul(a3, 0x0dU));
        (*state)[2][i] = (uint8_t)(gmul(a0, 0x0dU) ^ gmul(a1, 0x09U) ^ gmul(a2, 0x0eU) ^ gmul(a3, 0x0bU));
        (*state)[3][i] = (uint8_t)(gmul(a0, 0x0bU) ^ gmul(a1, 0x0dU) ^ gmul(a2, 0x09U) ^ gmul(a3, 0x0eU));
    }
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const roundkey_t rk)
{
    state_t state;
    uint8_t i, j, round;

    for (i = 0U; i < 4U; ++i)       /* i = row */
    {
        for (j = 0U; j < 4U; ++j)   /* j = col */
        {
            state[i][j] = in[i + (j * 4U)];
        }
    }

    add_round_key(0U, &state, rk);

    for (round = 1U; round < AES_ROUNDS; ++round)
    {
        sub_bytes(&state);
        shift_rows(&state);
        mix_columns(&state);
        add_round_key(round, &state, rk);
    }

    sub_bytes(&state);
    shift_rows(&state);
    add_round_key(AES_ROUNDS, &state, rk);

    for (i = 0U; i < 4U; ++i)
    {
        for (j = 0U; j < 4U; ++j)
        {
            out[i + (j * 4U)] = state[i][j];
        }
    }
}

static void aes_decrypt_block(const uint8_t in[16], uint8_t out[16], const roundkey_t rk)
{
    state_t state;
    uint8_t i, j, round;

    for (i = 0U; i < 4U; ++i)       /* i = row */
    {
        for (j = 0U; j < 4U; ++j)   /* j = col */
        {
            state[i][j] = in[i + (j * 4U)];
        }
    }

    add_round_key(AES_ROUNDS, &state, rk);

    for (round = AES_ROUNDS - 1U; round > 0U; --round)
    {
        inv_shift_rows(&state);
        inv_sub_bytes(&state);
        add_round_key(round, &state, rk);
        inv_mix_columns(&state);
    }

    inv_shift_rows(&state);
    inv_sub_bytes(&state);
    add_round_key(0U, &state, rk);

    for (i = 0U; i < 4U; ++i)
    {
        for (j = 0U; j < 4U; ++j)
        {
            out[i + (j * 4U)] = state[i][j];
        }
    }
}

int aes128_encrypt_buffer(const uint8_t *plaintext,
                           size_t        plaintextLen,
                           const uint8_t key[AES_KEY_SIZE],
                           uint8_t      *out,
                           size_t        outCapacity,
                           size_t       *outLen)
{
    roundkey_t rk;
    size_t paddedLen;
    uint8_t padValue;
    size_t numBlocks;
    size_t blockIdx;
    uint8_t block[AES_BLOCK_SIZE];

    if ((plaintext == NULL && plaintextLen != 0U) || (key == NULL) ||
        (out == NULL) || (outLen == NULL))
    {
        return -1;
    }

    padValue = (uint8_t)(AES_BLOCK_SIZE - (plaintextLen % AES_BLOCK_SIZE));
    paddedLen = plaintextLen + padValue;
    numBlocks = paddedLen / AES_BLOCK_SIZE;

    if (outCapacity < paddedLen)
    {
        return -1;
    }

    key_expansion(key, rk);

    for (blockIdx = 0U; blockIdx < numBlocks; ++blockIdx)
    {
        size_t offset = blockIdx * AES_BLOCK_SIZE;
        size_t i;

        for (i = 0U; i < AES_BLOCK_SIZE; ++i)
        {
            size_t srcIdx = offset + i;
            if (srcIdx < plaintextLen)
            {
                block[i] = plaintext[srcIdx];
            }
            else
            {
                block[i] = padValue;
            }
        }

        aes_encrypt_block(block, &out[offset], rk);
    }

    *outLen = paddedLen;
    return 0;
}

int aes128_decrypt_buffer(const uint8_t *ciphertext,
                           size_t         ciphertextLen,
                           const uint8_t  key[AES_KEY_SIZE],
                           uint8_t       *out,
                           size_t         outCapacity,
                           size_t        *outLen)
{
    roundkey_t rk;
    size_t numBlocks;
    size_t blockIdx;
    uint8_t padValue;
    size_t plainLen;

    if ((ciphertext == NULL) || (key == NULL) || (out == NULL) || (outLen == NULL))
    {
        return -1;
    }
    if ((ciphertextLen == 0U) || ((ciphertextLen % AES_BLOCK_SIZE) != 0U))
    {
        return -1;
    }
    if (outCapacity < ciphertextLen)
    {
        return -1;
    }

    key_expansion(key, rk);
    numBlocks = ciphertextLen / AES_BLOCK_SIZE;

    for (blockIdx = 0U; blockIdx < numBlocks; ++blockIdx)
    {
        size_t offset = blockIdx * AES_BLOCK_SIZE;
        aes_decrypt_block(&ciphertext[offset], &out[offset], rk);
    }

    padValue = out[ciphertextLen - 1U];
    if ((padValue == 0U) || (padValue > AES_BLOCK_SIZE) || (padValue > ciphertextLen))
    {
        return -1;
    }
    plainLen = ciphertextLen - padValue;

    *outLen = plainLen;
    return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *outHex)
{
    size_t i;
    for (i = 0U; i < len; ++i)
    {
        (void)snprintf(&outHex[i * 2U], 3U, "%02x", bytes[i]);
    }
    outHex[len * 2U] = '\0';
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t outCapacity, size_t *outLen)
{
    size_t hexLen;
    size_t byteLen;
    size_t i;

    if ((hex == NULL) || (out == NULL) || (outLen == NULL))
    {
        return -1;
    }

    hexLen = strlen(hex);
    if ((hexLen % 2U) != 0U)
    {
        return -1;
    }
    byteLen = hexLen / 2U;
    if (byteLen > outCapacity)
    {
        return -1;
    }

    for (i = 0U; i < byteLen; ++i)
    {
        unsigned int byteVal;
        if (sscanf(&hex[i * 2U], "%2x", &byteVal) != 1)
        {
            return -1;
        }
        out[i] = (uint8_t)byteVal;
    }

    *outLen = byteLen;
    return 0;
}

int aes128_encrypt_to_hex(const char *plaintext,
                           const uint8_t key[AES_KEY_SIZE],
                           char *outHex,
                           size_t outHexCap)
{
    uint8_t cipherBuf[MAX_ENCRYPTED_LEN_INTERNAL];
    size_t cipherLen = 0U;
    size_t plainLen;

    if ((plaintext == NULL) || (key == NULL) || (outHex == NULL))
    {
        return -1;
    }

    plainLen = strlen(plaintext);

    if (aes128_encrypt_buffer((const uint8_t *)plaintext, plainLen, key,
                               cipherBuf, sizeof(cipherBuf), &cipherLen) != 0)
    {
        return -1;
    }

    if (outHexCap < ((cipherLen * 2U) + 1U))
    {
        return -1;
    }

    bytes_to_hex(cipherBuf, cipherLen, outHex);
    return 0;
}

int aes128_decrypt_from_hex(const char *hexCipher,
                             const uint8_t key[AES_KEY_SIZE],
                             char *outPlain,
                             size_t outCap)
{
    uint8_t cipherBuf[MAX_ENCRYPTED_LEN_INTERNAL];
    uint8_t plainBuf[MAX_ENCRYPTED_LEN_INTERNAL];
    size_t cipherLen = 0U;
    size_t plainLen = 0U;

    if ((hexCipher == NULL) || (key == NULL) || (outPlain == NULL))
    {
        return -1;
    }

    if (hex_to_bytes(hexCipher, cipherBuf, sizeof(cipherBuf), &cipherLen) != 0)
    {
        return -1;
    }

    if (aes128_decrypt_buffer(cipherBuf, cipherLen, key, plainBuf, sizeof(plainBuf), &plainLen) != 0)
    {
        return -1;
    }

    if (outCap < (plainLen + 1U))
    {
        return -1;
    }

    memcpy(outPlain, plainBuf, plainLen);
    outPlain[plainLen] = '\0';
    return 0;
}
