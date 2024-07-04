#include "crm.h"
#include "logging.h"

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>

#include <gmp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#if 0
#define DO_NOT_OPTIMIZE(x) asm volatile("" : : "g"(x) : "memory")
#else
#define DO_NOT_OPTIMIZE(x) /* do nothing */
#endif

#define ORDER (1)
#define ENDIANESS (1)

#define MIN_PASS_LENGTH (8)
#define MIN_PASS_LENGTH_BIT (MIN_PASS_LENGTH_BIT * sizeof(char))
#define GENERATED_PASSWORD_LENGTH MIN_PASS_LENGTH

static const char const ALPHABET[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~";

static void *generate_random_string(char* s, const size_t L, const char *const alphabet, const size_t alphabet_size) {
  unsigned char buff;
  for (int i = 0; i < L; i++) {
    RAND_bytes(&buff, 1) ;
    s[i] = alphabet[buff % alphabet_size];
  }
  s[L] = '\0'; // Null-terminate the string
}

static void hash_f(char* out, const char* const in, size_t size) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, in, size);
  SHA256_Final(out, &sha256);
}


// ==============================================================


int MagicCrypt_PrepareKey(struct MagicCryptKey* key, const char* const password,
                          size_t size) {
  // TODO: remove comments
  // if (size < MIN_PASS_LENGTH) {
  //   return EINVAL;
  // }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  hash_f(hash, password, size);

  mpz_t msb;
  mpz_inits(msb, key->key, 0);
  mpz_import(key->key, sizeof(hash), ORDER, sizeof(hash[0]), ENDIANESS, 0, hash);

  mpz_ui_pow_ui(msb, 2, 256);
  mpz_add(key->key, key->key, msb);

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
  mpz_t rem, msb;
  mpz_inits(rem, msb, 0);
  
  mpz_ui_pow_ui(msb, 2, 256); // FIXME: remove magic constant

  char digest[SHA256_DIGEST_LENGTH];
  char *pass = malloc(GENERATED_PASSWORD_LENGTH + 1);
  if (NULL == pass) {
    return ENOMEM;
  }

  mpz_init(secondary_key->key);
  do {
    generate_random_string(pass, GENERATED_PASSWORD_LENGTH, ALPHABET, sizeof(ALPHABET));
    hash_f(digest, pass, sizeof(pass));

    mpz_import(secondary_key->key, GENERATED_PASSWORD_LENGTH, ORDER, sizeof(digest[0]), ENDIANESS, 0, digest);
    mpz_add(secondary_key->key, secondary_key->key, msb);

    mpz_gcd(rem, secondary_key->key, primary_key->key);
  } while (mpz_cmp_si(rem, 1) != 0);

  secondary_key->password = pass;
  secondary_key->password_size = GENERATED_PASSWORD_LENGTH;

  mpz_set(ctx->p1, primary_key->key);
  mpz_set(ctx->p2, secondary_key->key);

  mpz_clears(rem, msb, 0);

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

  LOG_DEBUG("k1: %Zd\nk2: %Zd\n", ctx->p1, ctx->p2);

  mpz_mul(P, ctx->p1, ctx->p2);
  LOG_DEBUG("P: %Zd\n", P);

  // Setup messages
  mpz_import(m1, size1, 1, 1, 0, 0, plaintext1);
  mpz_import(m2, size2, 1, 1, 0, 0, plaintext2);

  LOG_DEBUG("m1: %Zd\nm2: %Zd\n", m1, m2);

  // Find inverted element
  mpz_invert(p1_inv, ctx->p1, ctx->p2);
  mpz_invert(p2_inv, ctx->p2, ctx->p1);
  LOG_DEBUG("p1_inv: %Zd\np2_inv: %Zd\n", p1_inv, p2_inv);

  // p1 part
  mpz_mul(tmp1, m1, ctx->p2);
  mpz_mod(tmp1, tmp1, P);
  mpz_mul(tmp1, tmp1, p2_inv);
  mpz_mod(tmp1, tmp1, P);
  LOG_DEBUG("tmp1: %Zd\n", tmp1);

  // p2 part
  mpz_mul(tmp2, m2, ctx->p1);
  mpz_mod(tmp2, tmp2, P);
  mpz_mul(tmp2, tmp2, p1_inv);
  mpz_mod(tmp2, tmp2, P);
  LOG_DEBUG("tmp2: %Zd\n", tmp2);

  // Sum
  mpz_add(c, tmp1, tmp2);
  mpz_mod(c, c, P);
  LOG_DEBUG("c: %Zd\n", c);

  size_t proceed;
  mpz_export(output, &proceed, 1, 1, 0, 0, c);

  mpz_clears(m1, m2, c, p1_inv, p2_inv, tmp1, tmp2, P, 0);
  return proceed;
}

int MagicCrypt_Decrypt(const struct MagicCryptKey* key, const char* const input,
                       const size_t input_size, char* output, const size_t output_size) {
  mpz_t c, m1;
  mpz_inits(c, m1, 0);

  mpz_import(c, input_size, ORDER, sizeof(input[0]), ENDIANESS, 0, input);
  Zd(c); 
  mpz_mod(m1, c, key->key);
  Zd(m1);

  size_t proceed;
  mpz_export(output, &proceed, 1, 1, 0, 0, m1);

  mpz_clears(c, m1, 0);
  return proceed;
}