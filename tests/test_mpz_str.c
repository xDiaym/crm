#include <assert.h>
#include <crm.h>
#include <gmp.h>
#include "../src/crm.c"

int main() {
  const char pass[] = "h";
  char buff[256] = {0};

  struct MagicCryptKey k;
  MagicCrypt_PrepareKey(&k, pass, sizeof(pass));

  MagicCrypt_PasswordHexdigist(&k, buff, sizeof(buff));

  printf("pass: %s\n", pass);
  printf("f^-1(f(pass)): %s\n", buff);

  assert(strcmp(pass, buff) == 0 && "x != f^-1(f(x))");
  printf("OK\n");

  return 0;
}