.PHONY: build-tests run-tests

all: build-tests

build-tests: unbound-test

unbound-test: unbound-test.c $(UNBOUND_LIB)
	$(CC) -Wall -pedantic -std=c99 -g $< -o $@ -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -lunbound -lldns -lssl -lcrypto -lpthread -ldl

run-tests: unbound-test
	./unbound-test
