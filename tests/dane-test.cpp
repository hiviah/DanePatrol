#include <string>
#include <iostream>
#include <fstream>
#include <iterator>

#include "boost/assign/std/vector.hpp"

#include "Resolver.h"
#include "DANEAlgorithm.h"

using std::cout;
using std::endl;
using namespace boost::assign;

void expect(bool tested, const std::string& msg)
{
    if (!tested) throw(DANEException(msg));
}

std::string readFile(const char *fname)
{
    std::ifstream ifs(fname, std::ios_base::binary);
    std::string contents((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());

    return contents;
}

// NOERROR DNS reply
const int NOERROR = 0;

// The test will break once the tested TLSA record or real certificates change
int main(int argc, char **argv)
{
    try {
        std::string certStr = readFile("torproject.der");
        Certificate cert(certStr);

        Resolver resolver;
        TLSALookupResult lookup = resolver.fetchTLSA("www.torproject.org", 443);
        CertChain chain;
        chain.push_back(cert);
        DANEAlgorithm algo(chain);
        DANEMatch match;

        expect(lookup.result == 0 && lookup.rcode == NOERROR,
               "DNS resolution for torproject failed");

        // test will need update once the TLSA records change
        expect(lookup.tlsa.size() == 1, "Number of TLSA records for www.torproject.org changed");

        // Test with policy allowing cert usage 2 and 3
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01 | TLSAjs::ALLOW_TYPE_23);

        expect(match.successful && !match.abort && match.derCert == cert.asDer(),
               "TLSA association test failed");

        // test denying use of cert usage 2 and 3
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01);
        expect(!match.successful && !match.abort,
               "Policy association test failed");

        // mockup for cert usage 1 - change cert usage to 1 in TLSA
        lookup.tlsa[0].certUsage = TLSAjs::EE_CERT_PIN;
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01);

        expect(match.successful && !match.abort && match.derCert == cert.asDer(),
               "TLSA association for cert usage 1 failed");

        //  --- NLNETLABS.NL ---
        std::string nlnCert = readFile("nlnetlabs.nl.der"),
                    caCert3 = readFile("CAcertClass3.der"),
                    caCertRoot = readFile("CACertSigningAuthority_rootcert.der");
        chain = CertChain();
        chain += nlnCert,caCert3,caCertRoot; //boost::assign operator+=()

        lookup = resolver.fetchTLSA("nlnetlabs.nl", 443);
        algo = DANEAlgorithm(chain);

        expect(lookup.result == 0 && lookup.rcode == NOERROR,
               "DNS resolution for nlnetlabs.nl failed");

        // test will need update once the TLSA records change
        expect(lookup.tlsa.size() == 1, "Number of TLSA records for nlnetlabs.nl changed");

        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01);
        expect(match.successful && !match.abort && match.derCert == caCertRoot,
               "TLSA association for nlnetlabs failed");

        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_23);
        expect(!match.successful && !match.abort,
               "TLSA policy test for nlnetlabs failed");

        // mockup test for cert usage 2
        lookup.tlsa[0].certUsage = TLSAjs::CA_TA_ADDED;
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_23);
        expect(match.successful && !match.abort && match.derCert == caCertRoot,
               "TLSA association test for cert usage 2 failed");

        // test unknown matching type
        lookup.tlsa[0].matchingType = TLSAjs::MatchingType(42);
        lookup.tlsa[0].selector = TLSAjs::SPKI;
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01 | TLSAjs::ALLOW_TYPE_23);
        expect(!match.successful && !match.abort,
               "Failed test for unknown matching type");

        // test unknown selector
        lookup.tlsa[0].matchingType = TLSAjs::SHA256;
        lookup.tlsa[0].selector = TLSAjs::Selector(42);
        match = algo.check(lookup, TLSAjs::ALLOW_TYPE_01 | TLSAjs::ALLOW_TYPE_23);
        expect(!match.successful && !match.abort,
               "Failed test for unknown selector");

        // test malformed certificate - usable association, but no match => abort
        CertChain malformedChain;
        malformedChain += Certificate("EE malformed"),Certificate("CA malformed");
        DANEAlgorithm malformedChainAlgo(malformedChain);

        lookup.tlsa[0].matchingType = TLSAjs::SHA256;
        lookup.tlsa[0].selector = TLSAjs::SPKI; // SPKI causes cert to be parsed
        match = malformedChainAlgo.check(lookup, TLSAjs::ALLOW_TYPE_01 | TLSAjs::ALLOW_TYPE_23);
        expect(!match.successful && match.abort,
               "Failed test for malformed certificate");

    }
    catch (const std::exception& e) {
        cout << e.what() << endl;
        return 1;
    }

    cout << "DANE test passed" << endl;
    return 0;

    // Valgrind shows about 500 bytes from internal openssl structs still
    // reachable at the end, but the count doesn't grow if test body is
    // repeated in cycle.
}
