#ifndef CRM_H
#define CRM_H

// clang-format off
#include <stdio.h>
#include <gmp.h>
// clang-format on
#include <stddef.h>

#define BLOCK_SIZE_BITS (256)
#define BLOCK_SIZE (BLOCK_SIZE_BITS / (8 * sizeof(char)))

struct MagicCryptKey {
  char* password;
  size_t password_size;
  mpz_t key;
};

enum MagicCryptMode { ECB = 0, CBC };

struct MagicCryptCtx {
  int mode;
  mpz_t iv;
  mpz_t p1, p2;
};

int MagicCrypt_PrepareKey(struct MagicCryptKey* key, const char* const password,
                          size_t size);
void MagicCrypt_TeardownKey(struct MagicCryptKey* key);

int MagicCrypt_SetPassword(struct MagicCryptCtx* ctx,
                           const struct MagicCryptKey* primary_key,
                           struct MagicCryptKey* secondary_key);

void MagicCrypt_Setup(struct MagicCryptCtx* ctx);
void MagicCrypt_Teardown(struct MagicCryptCtx* ctx);

int MagicCrypt_Encrypt(struct MagicCryptCtx* ctx, const char* const plaintext1,
                       size_t size1, const char* const plaintext2, size_t size2,
                       char* output, size_t output_size);

int MagicCrypt_Decrypt(struct MagicCryptKey* key, const char* const input,
                       const size_t input_size, char* output,
                       const size_t output_size);

#endif  // CRM_H