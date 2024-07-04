CC?=gcc
CLFAGS+= -fsanitize=address -lgmp -lcrypto -std=c11 -ggdb -Iinclude

PHONY: all
all: crm-core

PHONY: crm-core
crm-core:
	$(CC) $(CLFAGS) src/main.c src/crm.c -o crm.out

.PHONY: format
format:
	find . -type f -name '*.[ch]' | xargs clang-format -i

.PHONY: test
test:
	$(CC) $(CLFAGS) tests/test_mpz_str.c src/crm.c -o test_mpz_str.out
	./test_mpz_str.out
	pytest tests

.PHONY:
clean:
	rm *.out *.o