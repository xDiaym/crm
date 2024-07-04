#include "crm.h"

#include <errno.h>
#include <memory.h>
#include <stdlib.h>
#include <assert.h>

#include <gmp.h>
#include "./base64.h"

#ifndef WARN
#define WARN(...) fprintf(stderr, "[WARN]: " __VA_ARGS__)
#else
#define WARN(...) /* nothing */
#endif

#if !(defined(_NDEBUG) || defined(NDEBUG))
#define LOG(...) gmp_fprintf(stderr, "[LOG]: " __VA_ARGS__)
#else
#define LOG(...) /* nothing */
#endif

#define GENERATED_PASS_SIZE (384)
#define BLOCK_SIZE_BITS (256)
#define BLOCK_SIZE (BLOCK_SIZE_BITS / (8 * sizeof(char)))

_Static_assert(GENERATED_PASS_SIZE > BLOCK_SIZE, "Password size can't be less than block size");

// static const char IV[BLOCK_SIZE] = {0x59, 0x61, 0x6e, 0x64, 0x65, 0x78, 0x26,
//                               0x49, 0x54, 0x4d, 0x4f, 0x5f, 0x74, 0x48,
//                               0x78, 0x5f, 0x34, 0x5f, 0x53, 0x74, 0x75,
//                               0x64, 0x43, 0x61, 0x6d, 0x70};
static const char IV[BLOCK_SIZE] = {0}; 

static void stompz(mpz_t x, const char* s) {
  char buff[BASE64_ENCODE_OUT_SIZE(BLOCK_SIZE)] = {0};
  base64_encode(s, BLOCK_SIZE, buff);

  for (int i = 0; i < sizeof(buff); ++i) {
    mpz_mul_2exp(x, x, 8);
    mpz_add_ui(x, x, buff[i]);
  }
}

static void mpztos(mpz_t x, char* s) {
  mpz_t y, rem;
  mpz_inits(y, rem, 0);
  mpz_set(y, x);

  char buff[BASE64_ENCODE_OUT_SIZE(BLOCK_SIZE)];
  for (int i = 0; i < sizeof(buff); ++i) {
    mpz_divmod_ui(y, rem, y, 256);

    buff[sizeof(buff) - i - 1] = mpz_get_ui(rem);
  }

  base64_decode(buff, sizeof(buff)-1, s);
  mpz_clears(y, rem, 0);
}

static void Mu(char* out, const char* const password, size_t size) {
  memcpy(out, IV, sizeof(IV));
  for (int i = 0; i < size; ++i) {
    out[i % BLOCK_SIZE] ^= password[i];
  }
}

static void MuInv(char* out, const char* const block) {
  memcpy(out, IV, sizeof(IV));
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    out[i] ^= block[i];
  }
}

static int min(int a, int b) { return a > b ? b : a; }

// ==============================================================

int MagicCrypt_PrepareKey(struct MagicCryptKey* key, const char* const password,
                          size_t size) {
  char buff[BLOCK_SIZE];
  Mu(buff, password, size);

  mpz_init(key->key);
  stompz(key->key, buff);

  return 1;
}

void MagicCrypt_TeardownKey(struct MagicCryptKey* key) {
  mpz_clear(key->key);
  // FIXME(all): memset(0)
}

int MagicCrypt_SetPassword(struct MagicCryptCtx* ctx,
                           const struct MagicCryptKey* primary_key,
                           struct MagicCryptKey* secondary_key) {
  mpz_t rem;
  mpz_init(rem);

  mpz_init(secondary_key->key);
  int is_coprime = 0, is_large_enough = 0;
  do {
    mpz_random(secondary_key->key, GENERATED_PASS_SIZE);

    mpz_gcd(rem, secondary_key->key, primary_key->key);
    is_coprime = mpz_cmp_si(rem, 1) == 0;
    is_large_enough = mpz_sizeinbase(secondary_key->key, 2) > BLOCK_SIZE;
  } while (!(is_coprime && is_large_enough));

  mpz_clear(rem);

  return 1;
}

int MagicCrypt_PasswordHexdigist(const struct MagicCryptKey* key, char* buffer,
                                 size_t size) {
  const int len = GENERATED_PASS_SIZE / (8 * sizeof(char));
  char buff[len];
  mpztos(key->key, buff);

  MuInv(buffer, buff);

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
  mpz_t m1, m2, c, tmp1, tmp2, P;
  mpz_inits(m1, m2, c, tmp1, tmp2, P, 0);

  mpz_clears(m1, m2, c, tmp1, tmp2, P, 0);
  return 1;
}

int MagicCrypt_Decrypt(const struct MagicCryptKey* key, const char* input,
                       size_t input_size, char* output, size_t output_size) {
  return 1;
}