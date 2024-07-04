#include "../src/crm.c"
#include <assert.h>
#include <gmp.h>
#include <crm.h>

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
  // mpz_t x;
  // mpz_init(x);
  // char buff[256] = {'h', 0};
  // char buff2[256] = {0};
  // stompz(x, buff);

  // gmp_printf("%Zd\n", x);

  // mpztos(x, buff2);

  // printf("%s\n", buff2);

  // mpz_clear(x);
  return 0;
}