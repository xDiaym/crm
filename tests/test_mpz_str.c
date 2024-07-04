#include <assert.h>
#include <crm.h>
#include <gmp.h>

int main() {
  const char pass[] = "h";
  char buff[256] = {0};

  struct MagicCryptCtx ctx;
  struct MagicCryptKey k1, k2;
  MagicCrypt_PrepareKey(&k1, pass, sizeof(pass));
  MagicCrypt_SetPassword(&ctx, &k1, &k2);

  printf("pass1: %s\n", k1.password);
  printf("pass2: %s\n", k2.password);

  printf("OK\n");

  MagicCrypt_TeardownKey(&k1);
  MagicCrypt_TeardownKey(&k2);

  return 0;
}