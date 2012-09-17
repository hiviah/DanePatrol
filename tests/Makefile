.PHONY: build-tests run-tests clean-tests

all: build-tests

OPENSSL_LIB := ../libs/openssl
LDNS_LIB := ../libs/ldns
UNBOUND_LIB := ../libs/unbound
NPAPI_LIB := ../FireBreath/build/bin/TLSAfetcher
NPAPI_LINK := -Wl,-\( $(NPAPI_LIB)/npTLSAfetcher.so -Wl,-\)
DANE_CORE_LIB := ../FireBreath/build/projects/TLSAfetcher/libDANECore.a

PLUGIN_SOURCE_DIR := ../plugin-source/TLSAfetcher
FB_DIR := ../FireBreath
FB_INCLUDE := -I$(FB_DIR)/src/ScriptingCore -I$(FB_DIR)/src/config

INCLUDES := -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -I$(PLUGIN_SOURCE_DIR) $(FB_INCLUDE)
LIBS := -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -lunbound -lldns -lssl -lcrypto -lpthread -ldl

CFLAGS += $(INCLUDES) -Wall -pedantic -std=c99 -g
CXXFLAGS += $(INCLUDES) -Wall -g
LDFLAGS += $(DANE_CORE_LIB) $(LIBS)

TARGETS := unbound-test resolver-test

## Generic targets

build-tests: $(TARGETS)

run-tests: build-tests
	./unbound-test
	./resolver-test
	./certificate-test

clean-tests:
	rm -f $(TARGETS)

## Separate test builds

unbound-test: unbound-test.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

resolver-test: resolver-test.cpp $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CXX) $< -o $@ $(CXXFLAGS) $(LDFLAGS)

certificate-test: certificate-test.cpp $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CXX) $< -o $@ $(CXXFLAGS) $(LDFLAGS)
