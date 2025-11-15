/**
 * @file KStream.c
 * @author Shane Girolamo
 *
 * @brief Implementation of the KStream Abstract Data Type (ADT).
 *
 * This module implements a symmetric-key stream cipher that generates a
 * pseudorandom keystream from an 8-byte (64-bit) key. Each keystream byte
 * is XORed with an input byte to produce a translated output byte.
 */

#include "KStream.h"
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

/**
 * @brief Internal types and helpers for the keystream implementation.
 */

/**
 * @brief Unsigned 8-bit byte type, per assignment suggestion.
 */
typedef uint8_t byte;

/**
 * @brief Opaque struct definition (visible only in this file).
 */
struct KStream
{
    byte key[8]; /**< 8-byte key, derived from uint64_t input. */
    int keylen;  /**< Length of key in bytes (always 8 here). */
    byte S[256]; /**< State array for the cipher. */
    int i;       /**< First permutation index. */
    int j;       /**< Second permutation index. */
};

/**
 * @brief Swap the values of two bytes.
 *
 * @param a Pointer to first byte.
 * @param b Pointer to second byte.
 */
static inline void swap_bytes(byte *a, byte *b)
{
    byte tmp = *a;
    *a = *b;
    *b = tmp;
}

/**
 * @brief Generate the next byte of the keystream.
 *
 * Implements the "next_byte" pseudocode from the assignment:
 *
 *   i := (i + 1) mod 256
 *   j := (j + S[i]) mod 256
 *   swap S[i], S[j]
 *   B := S[(S[i] + S[j]) mod 256]
 *   return B
 *
 * @param ks  A valid KStream instance.
 *
 * @return Next keystream byte.
 *
 * @pre  ks is not NULL and has been initialized.
 */
static byte ks_next_byte(KStream *ks)
{
    assert(ks != NULL);

    ks->i = (ks->i + 1) & 0xFF;
    ks->j = (ks->j + ks->S[ks->i]) & 0xFF;

    swap_bytes(&ks->S[ks->i], &ks->S[ks->j]);

    byte idx = (byte)((ks->S[ks->i] + ks->S[ks->j]) & 0xFF);
    return ks->S[idx];
}

/**
 * @brief Create and initialize a KStream instance from the provided key.
 *
 * @param keybytes  Eight-byte array containing the binary key data.
 *
 * @return Pointer to the initialized KStream structure.
 */
KStream *ks_create(const uint8_t keybytes[8])
{
    KStream *ks = malloc(sizeof(KStream));
    assert(ks != NULL);

    for (int i = 0; i < 8; i++)
    {
        ks->key[i] = keybytes[i];
    }
    ks->keylen = 8;

    for (int i = 0; i < 256; i++)
    {
        ks->S[i] = (byte)i;
    }

    ks->i = 0;
    ks->j = 0;

    for (int i = 0; i < 256; i++)
    {
        ks->j = (ks->j + ks->S[i] + ks->key[i % ks->keylen]) & 0xFF;
        swap_bytes(&ks->S[i], &ks->S[ks->j]);
    }

    ks->i = 0;
    for (int n = 0; n < 1024; n++)
    {
        (void)ks_next_byte(ks);
    }

    return ks;
}

/**
 * @brief Destroy a KStream instance and release its memory.
 *
 * @param ks  Instance to destroy (may be NULL).
 */
void ks_destroy(KStream *ks)
{
    if (ks == NULL)
    {
        return;
    }

    free(ks);
}

/**
 * @brief Translate bytes using the keystream.
 *
 * Uses XOR with successive keystream bytes to turn plaintext into ciphertext
 * or ciphertext back into plaintext.
 *
 * @param ks   Initialized KStream instance.
 * @param in   Input buffer containing plaintext or ciphertext data.
 * @param out  Output buffer that receives translated bytes.
 * @param num  Number of bytes to translate.
 */
void ks_translate(KStream *ks, const uint8_t *in, uint8_t *out, size_t num)
{
    assert(ks != NULL);
    if (num == 0)
    {
        return;
    }
    assert(in != NULL);
    assert(out != NULL);

    for (size_t i = 0; i < num; i++)
    {
        byte k = ks_next_byte(ks);
        out[i] = in[i] ^ k;
    }
}
