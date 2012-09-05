.PHONY: all submodules libs-build
all: libs-build

CFLAGS=-fPIC
export CFLAGS

LIBS_SOURCE = libs-source
OPENSSL_TARBALL = $(LIBS_SOURCE)/openssl-1.0.1c.tar.gz
LDNS_TARBALL = $(LIBS_SOURCE)/ldns-1.6.13.tar.gz
UNBOUND_TARBALL = $(LIBS_SOURCE)/unbound-1.4.18.tar.gz

BASEDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

OPENSSL_DIR := $(BASEDIR)/libs/openssl-1.0.1c
LDNS_DIR := $(BASEDIR)/libs/ldns-1.6.13
UNBOUND_DIR := $(BASEDIR)/libs/unbound-1.4.18

OPENSSL_LIB := $(BASEDIR)/libs/openssl
LDNS_LIB := $(BASEDIR)/libs/ldns
UNBOUND_LIB := $(BASEDIR)/libs/unbound

FIREBREATH_DIR = $(BASEDIR)/FireBreath
FIREBREATH_TAG = firebreath-1.6.0

libs-build: submodules libs $(OPENSSL_LIB) $(LDNS_LIB) $(UNBOUND_LIB)

submodules:
	git submodule update --init --recursive
	(cd $(FIREBREATH_DIR) && git checkout $(FIREBREATH_TAG))

libs:
	mkdir libs

## openssl
$(OPENSSL_LIB): $(OPENSSL_DIR)
	(cd $< && ./config no-shared no-krb5 --prefix=$@ -fPIC && make && make install)

$(OPENSSL_DIR): $(OPENSSL_TARBALL)
	tar xzf $< -C libs

## ldns
$(LDNS_LIB): $(LDNS_DIR) $(OPENSSL_LIB)
	(cd $< && ./configure --disable-shared --with-ssl=$(OPENSSL_LIB) --with-pic --prefix=$@ && make && make install)

$(LDNS_DIR): $(LDNS_TARBALL)
	tar xzf $< -C libs

## unbound
$(UNBOUND_LIB): $(UNBOUND_DIR) $(LDNS_LIB) $(OPENSSL_LIB)
	(cd $< && ./configure --disable-shared --with-ssl=$(OPENSSL_LIB) --with-ldns=$(LDNS_LIB) --without-libevent --with-pic --prefix=$@ && make && make install)

$(UNBOUND_DIR): $(UNBOUND_TARBALL)
	tar xzf $< -C libs

unbound-test: unbound-test.c libs-build
	$(CC) -Wall -pedantic -std=c99 -g $< -o $@ -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -lunbound -lldns -lssl -lcrypto -lpthread -ldl

test: unbound-test
	./unbound-test

distclean:
	rm -rf libs
