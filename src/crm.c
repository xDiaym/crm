#include "crm.h"

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>

#include <gmp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define DO_NOT_OPTIMIZE(x) asm volatile("" : : "g"(x) : "memory")

#define ORDER (1)
#define ENDIANESS (1)

#define MIN_PASS_LENGTH (8)
#define MIN_PASS_LENGTH_BIT (MIN_PASS_LENGTH_BIT * sizeof(char))

// ==============================================================

int MagicCrypt_PrepareKey(struct MagicCryptKey* key, const char* const password,
                          size_t size) {
  if (size < MIN_PASS_LENGTH) {
    return EINVAL;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, password, size);
  SHA256_Final(hash, &sha256);

  mpz_t msb;
  mpz_inits(msb, key->key, 0);
  mpz_import(key->key, sizeof(hash), ORDER, sizeof(hash[0]), ENDIANESS, 0, hash);

  mpz_set(msb, 1);
  mpz_
  mpz_add();

  key->password = malloc(sizeof(char) * size);
  if (key->password == NULL) {
    return ENOMEM;
  }

  memcpy(key->password, password, size);
  key->password_size = size;

  mpz_clear(msb);

  return 1;
}

void MagicCrypt_TeardownKey(struct MagicCryptKey* key) {
  // FIXME: key->key должен быть занулен
  mpz_clear(key->key);

  memset(key->password, 0, key->password_size);
  DO_NOT_OPTIMIZE(key->password[0]);
  free(key->password);
}

int MagicCrypt_SetPassword(struct MagicCryptCtx* ctx,
                           const struct MagicCryptKey* primary_key,
                           struct MagicCryptKey* secondary_key) {
  mpz_t rem;
  mpz_init(rem);

  mpz_init(secondary_key->key);
  int is_coprime = 0, is_large_enough = 0;
  do {
    mpz_random(secondary_key->key, INTERNAL_PASS_SIZE_BITS);

    mpz_gcd(rem, secondary_key->key, primary_key->key);
    is_coprime = mpz_cmp_si(rem, 1) == 0;
    is_large_enough = mpz_sizeinbase(secondary_key->key, 2) > BLOCK_SIZE_BITS;
  } while (!(is_coprime && is_large_enough));

  mpz_clear(rem);

  return 1;
}

void MagicCrypt_Setup(struct MagicCryptCtx* ctx) {
  mpz_inits(ctx->p1, ctx->p2, 0);
}

void MagicCrypt_Teardown(struct MagicCryptCtx* ctx) {
  mpz_clears(ctx->p1, ctx->p2, 0);
}

int MagicCrypt_Encrypt(struct MagicCryptCtx* ctx, const char* const plaintext1,
                       size_t size1, const char* const plaintext2, size_t size2,
                       char* output, size_t output_size) {
  mpz_t m1, m2, c, p1_inv, p2_inv, tmp1, tmp2, P;
  mpz_inits(m1, m2, c, tmp1, tmp2, P, 0);

  mpz_mul(P, ctx->p1, ctx->p2);

  // Setup messages
  mpz_import(m1, size1, 1, 1, 0, 0, m1);
  mpz_import(m2, size2, 1, 1, 0, 0, m2);

  // Find inverted element
  mpz_invert(p1_inv, ctx->p1, ctx->p2);
  mpz_invert(p2_inv, ctx->p2, ctx->p1);

  // p1 part
  mpz_mul(tmp1, m1, ctx->p2);
  mpz_mod(tmp1, tmp1, P);
  mpz_mul(tmp1, tmp1, p2_inv);
  mpz_mod(tmp1, tmp1, P);

  // p2 part
  mpz_mul(tmp2, m2, ctx->p1);
  mpz_mod(tmp1, tmp1, P);
  mpz_mul(tmp2, tmp2, p1_inv);
  mpz_mod(tmp1, tmp1, P);

  // Sum
  mpz_add(c, tmp1, tmp2);
  mpz_mod(tmp1, tmp1, P);

  size_t proceed;
  mpz_export(output, &proceed, 1, 1, 0, 0, c);

  mpz_clears(m1, m2, c, tmp1, tmp2, P, 0);
  return 1;
}

int MagicCrypt_Decrypt(const struct MagicCryptKey* key, const char* input,
                       size_t input_size, char* output, size_t output_size) {
  mpz_t c, m1;
  mpz_inits(c, m1, 0);

  mpz_import(c, input_size, 1, 1, 0, 0, input);

  mpz_mod(m1, c, key->key);

  size_t proceed;
  mpz_export(output, &proceed, 1, 1, 0, 0, m1);

  mpz_clears(c, m1, 0);
  return 1;
}