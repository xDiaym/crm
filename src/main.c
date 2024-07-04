#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "./crm.h"

int main() {
  const char m1[] = "hello, world!";
  const char m2[] = "secret";
  char buff1[1024] = {0}, buff2[1024] = {0};

  const char key1[] = "itmo&yandex";

  struct MagicCryptKey k1, k2;
  struct MagicCryptCtx ctx;

  if (!MagicCrypt_PrepareKey(&k1, key1, sizeof(key1))) {
    printf("problem with password");
    return -1;
  }
  MagicCrypt_Setup(&ctx);
  MagicCrypt_SetPassword(&ctx, &k1, &k2);

  printf("Pass1: %s\n", k1.password);
  printf("Generated Pass2: %s\n", k2.password);

  int size = MagicCrypt_Encrypt(&ctx, m1, sizeof(m1), m2, sizeof(m2), buff1,
                     sizeof(buff1));
  printf("Ecrypted: %s\n", buff1);

  MagicCrypt_Decrypt(&k1, buff1, size, buff2, sizeof(buff2));
  printf("decrypted with Key1: %s\n", buff2);

  MagicCrypt_Decrypt(&k2, buff1, size, buff2, sizeof(buff2));
  printf("decrypted with Key2: %s\n", buff2);

  MagicCrypt_TeardownKey(&k1);
  MagicCrypt_TeardownKey(&k2);
  MagicCrypt_Teardown(&ctx);
}
