CC?=gcc

PHONY: all
all: crm-core

PHONY: crm-core
crm-core:
	$(CC) -ggdb -std=c11 -Iinclude src/main.c src/crm.c -lgmp -o crm.out

.PHONY: format
format:
	find . -type f -name '*.[ch]' | xargs clang-format -i

.PHONY: test
test:
	pytest tests
