#include "crm.h"
#include "logging.h"

#include <assert.h>
#include <errno.h>
#include <memory.h>
#include <stdlib.h>

#include <gmp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#if defined(_MSVC_VER)
#error Win32 not supported
#else
#define DO_NOT_OPTIMIZE(x) __asm__ volatile("" : "+m"(x) : : "memory")
#endif

#define ORDER (1)
#define ENDIANESS (1)

#define MIN_PASS_LENGTH (8)
#define MIN_PASS_LENGTH_BIT (MIN_PASS_LENGTH_BIT * sizeof(char))
#define GENERATED_PASSWORD_LENGTH MIN_PASS_LENGTH

#if defined(__clang__) || defined(__GNUC__)
#define FORCE_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE inline
#endif

static int max(int a, int b) { return a > b ? a : b; }
static int min(int a, int b) { return a > b ? b : a; }

static const char const ALPHABET[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&\'()*"
    "+,-./:;<=>?@[\\]^_`{|}~";

static void* generate_random_string(char* s, const size_t L,
                                    const char* const alphabet,
                                    const size_t alphabet_size) {
  unsigned char buff;
  for (int i = 0; i < L; i++) {
    RAND_bytes(&buff, 1);
    s[i] = alphabet[buff % alphabet_size];
  }
  s[L] = '\0';  // Null-terminate the string
}

static void hash_f(char* out, const char* const in, size_t size) {
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, in, size);
  SHA256_Final(out, &sha256);
}

static FORCE_INLINE void mpz_safe_clear(mpz_t x) {
  memset(x->_mp_d, 0, x->_mp_alloc * sizeof(mp_limb_t));
  DO_NOT_OPTIMIZE(x->_mp_d);
  mpz_clear(x);
}

// ==============================================================

int MagicCrypt_PrepareKey(struct MagicCryptKey* key, const char* const password,
                          size_t size) {
  if (size < MIN_PASS_LENGTH) {
    return EINVAL;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  hash_f(hash, password, size);

  mpz_t msb;
  mpz_inits(msb, key->key, 0);
  mpz_import(key->key, sizeof(hash), ORDER, sizeof(hash[0]), ENDIANESS, 0,
             hash);

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
  memset(key->key->_mp_d, 0, key->key->_mp_alloc * sizeof(mp_limb_t));
  DO_NOT_OPTIMIZE(key->key->_mp_d);
  mpz_clear(key->key);

  memset(key->password, 0, key->password_size);
  free(key->password);
  DO_NOT_OPTIMIZE(key->password[0]);

  key->password_size = 0;
  DO_NOT_OPTIMIZE(key->password_size);

  memset(key, 0, sizeof(struct MagicCryptKey));
  DO_NOT_OPTIMIZE(key);
}

int MagicCrypt_SetPassword(struct MagicCryptCtx* ctx,
                           const struct MagicCryptKey* primary_key,
                           struct MagicCryptKey* secondary_key) {
  mpz_t rem, msb;
  mpz_inits(rem, msb, 0);

  mpz_ui_pow_ui(msb, 2, 256);  // FIXME: remove magic constant

  char digest[SHA256_DIGEST_LENGTH];
  char* pass = malloc(GENERATED_PASSWORD_LENGTH + 1);
  if (NULL == pass) {
    return ENOMEM;
  }

  mpz_init(secondary_key->key);
  do {
    generate_random_string(pass, GENERATED_PASSWORD_LENGTH, ALPHABET,
                           sizeof(ALPHABET));
    hash_f(digest, pass, sizeof(pass));

    mpz_import(secondary_key->key, GENERATED_PASSWORD_LENGTH, ORDER,
               sizeof(digest[0]), ENDIANESS, 0, digest);
    mpz_add(secondary_key->key, secondary_key->key, msb);

    mpz_gcd(rem, secondary_key->key, primary_key->key);
  } while (mpz_cmp_si(rem, 1) != 0);

  secondary_key->password = pass;
  secondary_key->password_size = GENERATED_PASSWORD_LENGTH;

  mpz_set(ctx->p1, primary_key->key);
  mpz_set(ctx->p2, secondary_key->key);

  // ^=== find second password
  // v=== setup context

  mpz_mul(ctx->P, ctx->p1, ctx->p2);
  // Find inverted elemen
  mpz_invert(ctx->p1_inv, ctx->p1, ctx->p2);
  mpz_invert(ctx->p2_inv, ctx->p2, ctx->p1);

  mpz_clears(rem, msb, 0);

  return 1;
}

void MagicCrypt_Setup(struct MagicCryptCtx* ctx) {
  mpz_inits(ctx->p1, ctx->p2, ctx->p1_inv, ctx->p2_inv, ctx->P, 0);
}

void MagicCrypt_Teardown(struct MagicCryptCtx* ctx) {
  memset(ctx->p1->_mp_d, 0, ctx->p1->_mp_alloc * sizeof(mp_limb_t));
  DO_NOT_OPTIMIZE(ctx->p1->_mp_d);

  memset(ctx->p2->_mp_d, 0, ctx->p2->_mp_alloc * sizeof(mp_limb_t));
  DO_NOT_OPTIMIZE(ctx->p2->_mp_d);

  mpz_safe_clear(ctx->p1_inv);
  mpz_safe_clear(ctx->p2_inv);
  mpz_safe_clear(ctx->P);

  mpz_clears(ctx->p1, ctx->p2, 0);
}

int MagicCrypt_EncryptBlock(struct MagicCryptCtx* ctx, const char* const block1,
                            const char* const block2, char* out) {
  mpz_t m1, m2, tmp1, tmp2, c;
  mpz_inits(m1, m2, tmp1, tmp2, c, 0);

  mpz_import(m1, BLOCK_SIZE, 1, 1, 0, 0, block1);
  mpz_import(m2, BLOCK_SIZE, 1, 1, 0, 0, block2);

  // p1 part
  mpz_mul(tmp1, m1, ctx->p2);
  mpz_mod(tmp1, tmp1, ctx->P);
  mpz_mul(tmp1, tmp1, ctx->p2_inv);
  mpz_mod(tmp1, tmp1, ctx->P);

  // p2 part
  mpz_mul(tmp2, m2, ctx->p1);
  mpz_mod(tmp2, tmp2, ctx->P);
  mpz_mul(tmp2, tmp2, ctx->p1_inv);
  mpz_mod(tmp2, tmp2, ctx->P);

  // Sum
  mpz_add(c, tmp1, tmp2);
  mpz_mod(c, c, ctx->P);

  size_t proceed;
  memset(out, 0, 2 * BLOCK_SIZE + 1);
  mpz_export(out, &proceed, 1, 1, 0, 0, c);

  mpz_clears(m1, m2, tmp1, tmp2, c, 0);
  return 2 * BLOCK_SIZE + 1;
}

int MagicCrypt_Encrypt(struct MagicCryptCtx* ctx, const char* const plaintext1,
                       size_t size1, const char* const plaintext2, size_t size2,
                       char* output, size_t output_size) {
  mpz_t m1, m2, c, tmp1, tmp2;
  mpz_inits(m1, m2, c, tmp1, tmp2, 0);

  char block1[BLOCK_SIZE], block2[BLOCK_SIZE];

  size_t bytes_readen = 0, bytes_written = 0;
  while (bytes_readen < max(size1, size2)) {
    memset(block1, 0, sizeof(block1));
    const int n1 = min(size1 - bytes_readen, BLOCK_SIZE);
    if (n1 > 0) {
      memcpy(block1, plaintext1 + bytes_readen, n1);
    }

    memset(block2, 0, sizeof(block2));
    const int n2 = min(size2 - bytes_readen, BLOCK_SIZE);
    if (n2 > 0) {
      memcpy(block2, plaintext2 + bytes_readen, n2);
    }

    bytes_readen += BLOCK_SIZE;

    bytes_written +=
        MagicCrypt_EncryptBlock(ctx, block1, block2, output + bytes_written);
  }
  return bytes_written;
}

int MagicCrypt_DecryptBlock(const struct MagicCryptKey* key,
                            char block[2 * BLOCK_SIZE + 1], char* out) {
  mpz_t c, m1;
  mpz_inits(c, m1, 0);

  size_t block_size =
      block[2 * BLOCK_SIZE] == 0 ? 2 * BLOCK_SIZE : 2 * BLOCK_SIZE + 1;
  mpz_import(c, block_size, ORDER, sizeof(block[0]), ENDIANESS, 0, block);
  mpz_mod(m1, c, key->key);

  size_t proceed;
  mpz_export(out, &proceed, 1, 1, 0, 0, m1);

  mpz_clears(c, m1, 0);
  return proceed;
}

int MagicCrypt_Decrypt(const struct MagicCryptKey* key, const char* const input,
                       const size_t input_size, char* output,
                       const size_t output_size) {
  size_t bytes_written = 0, bytes_readen = 0;
  char block[2 * BLOCK_SIZE + 1];

  while (bytes_readen < input_size) {
    const int n = min(input_size - bytes_readen, 2 * BLOCK_SIZE + 1);
    memset(block, 0, sizeof(block));
    memcpy(block, input + bytes_readen, n);
    bytes_readen += n;

    bytes_written +=
        MagicCrypt_DecryptBlock(key, block, output + bytes_written);
  }

  return bytes_readen;
}