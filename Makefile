all: libs

OPENSSL_TARBALL = libs-source/openssl-1.0.1c.tar.gz
LDNS_TARBALL = libs-source/ldns-1.6.13.tar.gz
UNBOUND_TARBALL = libs-source/unbound-1.4.18.tar.gz

BASEDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

OPENSSL_DIR := $(BASEDIR)/libs/openssl-1.0.1c
LDNS_DIR := $(BASEDIR)/libs/ldns-1.6.13
UNBOUND_DIR := $(BASEDIR)/libs/unbound-1.4.18

OPENSSL_LIB := $(BASEDIR)/libs/openssl
LDNS_LIB := $(BASEDIR)/libs/ldns
UNBOUND_LIB := $(BASEDIR)/libs/unbound

libs: $(OPENSSL_LIB) $(LDNS_LIB) $(UNBOUND_LIB)

## openssl
$(OPENSSL_LIB): $(OPENSSL_DIR)
	(cd $< && ./config no-shared no-krb5 --prefix=$@ && make && make install)

$(OPENSSL_DIR): $(OPENSSL_TARBALL)
	tar xzf $< -C libs

## ldns
$(LDNS_LIB): $(LDNS_DIR) $(OPENSSL_LIB)
	(cd $< && ./configure --disable-shared --with-ssl=$(OPENSSL_LIB) --prefix=$@ && make && make install)

$(LDNS_DIR): $(LDNS_TARBALL)
	tar xzf $< -C libs

## unbound
$(UNBOUND_LIB): $(UNBOUND_DIR) $(LDNS_LIB) $(OPENSSL_LIB)
	(cd $< && ./configure --disable-shared --with-ssl=$(OPENSSL_LIB) --with-ldns=$(LDNS_LIB) --without-libevent --prefix=$@ && make && make install)

$(UNBOUND_DIR): $(UNBOUND_TARBALL)
	tar xzf $< -C libs

unbound-test: unbound-test.c $(UNBOUND_LIB) $(LDNS_LIB) $(OPENSSL_LIB)
	$(CC) -g $< -o $@ -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -lunbound -lldns -lssl -lcrypto -lpthread -ldl
