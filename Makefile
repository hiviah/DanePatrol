.PHONY: all submodules libs-build plugin prepmake
all: libs-build plugin

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

PLUGIN_SOURCE_DIR = $(BASEDIR)/plugin-source/TLSAfetcher
PLUGIN_BUILD_DIR = $(FIREBREATH_DIR)/build

## uncomment to make plugin build verbose - shows gcc invocations etc.
#PLUGIN_VERBOSE_BUILD = VERBOSE=1

## Configuration is one of Debug, Release, MinSizeRel and RelWithDebInfo.
## You need to run 'make prepmake' after changing.
PLUGIN_CONFIGURATION = Debug

libs-build: submodules libs $(OPENSSL_LIB) $(LDNS_LIB) $(UNBOUND_LIB)

submodules:
	git submodule update --init --recursive
	(cd $(FIREBREATH_DIR) && git checkout $(FIREBREATH_TAG))

libs:
	mkdir libs

## openssl
$(OPENSSL_LIB): $(OPENSSL_DIR)
	(cd $< && ./config no-shared no-krb5 --prefix=$@ -fPIC && make -j1 && make -j1 install)

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

## plugin
plugin: $(PLUGIN_BUILD_DIR) $(UNBOUND_LIB)
	make $(PLUGIN_VERBOSE_BUILD) -C $<

plugin-nodeps:
	make $(PLUGIN_VERBOSE_BUILD) -C $(PLUGIN_BUILD_DIR)

prepmake:
	$(FIREBREATH_DIR)/prepmake.sh $(PLUGIN_SOURCE_DIR) -D CMAKE_BUILD_TYPE=$(PLUGIN_CONFIGURATION)

$(PLUGIN_BUILD_DIR): $(PLUGIN_SOURCE_DIR)/CMakeLists.txt $(PLUGIN_SOURCE_DIR)/PluginConfig.cmake \
		$(PLUGIN_SOURCE_DIR)/X11/projectDef.cmake $(PLUGIN_SOURCE_DIR)/Mac/projectDef.cmake $(PLUGIN_SOURCE_DIR)/Win/projectDef.cmake \
		#dependencies end
		make prepmake


## tests
unbound-test: unbound-test.c $(UNBOUND_LIB)
	$(CC) -Wall -pedantic -std=c99 -g $< -o $@ -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -lunbound -lldns -lssl -lcrypto -lpthread -ldl

test: unbound-test
	./unbound-test


## cleaning
clean:
	[ -d "$(PLUGIN_BUILD_DIR)" ] && make -C "$(PLUGIN_BUILD_DIR)" clean

distclean:
	rm -rf libs
	rm -rf $(PLUGIN_BUILD_DIR)
