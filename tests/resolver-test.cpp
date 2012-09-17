#include <string>
#include <iostream>

#include "Resolver.h"

using std::cout;
using std::endl;

void expect(bool tested, const std::string& msg)
{
    if (!tested) throw(ResolverException(msg));
}

int main(int argc, char **argv)
{
    try {
        Resolver resolver;
        TLSALookupResult tlsa = resolver.fetchTLSA("www.torproject.org", 443);
        std::string knownAssocHex = "a01bfa93ecac24481618e4c589e9ec0ffbe34c416a0eb5f77a387dd9657dbb45";

        expect(tlsa.result == 0, "Resolve failure");
        expect(tlsa.rcode == 0, "Rcode != NOERROR");
        expect(tlsa.tlsa.size() > 0, "TLSA result present");
        expect(tlsa.dnssecStatus == TLSAjs::SECURE, "DNSSEC validation status != secure");

        ResolvedTLSA rr = tlsa.tlsa.front();
        std::string assocHex = rr.associationHex;
        std::string assocBin = rr.association;

        expect(rr.certUsage == TLSAjs::EE_TA_ADDED, "Unexpected cert usage");
        expect(rr.matchingType == TLSAjs::SHA256, "Unexpected matching type");
        expect(rr.selector == TLSAjs::SPKI, "Unexpected selector");
        expect(assocHex == knownAssocHex, "Testing against known TLSA data failed.");
        expect(hex2bin(assocHex) == assocBin, "Hex-bin conversion broke.");
    }
    catch (const ResolverException& e) {
        cout << e.message() << endl;
        return 1;
    }

    cout << "Resolver test passed" << endl;
    return 0;
}
