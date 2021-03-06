#include <string>
#include <iostream>
#include <fstream>
#include <iterator>

#include "Resolver.h"
#include "DANEAlgorithm.h"

using std::cout;
using std::endl;

/*
 * Exporting SPKI: 
 * openssl x509 -inform der -in certificate.der -pubkey -noout | grep -v -e '^--' | base64 -d > spki.der
 *
 * Parsing SPKI (with openssl and Peter Gutmann's dumpasn1):
 * openssl asn1parse -dump -i -inform der -in spki.der
 * dumpasn1 spki.der
 *
 *    0  290: SEQUENCE {
 *    4   13:   SEQUENCE {
 *    6    9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 *   17    0:     NULL
 *          :     }
 *   19  271:   BIT STRING, encapsulates {
 *   24  266:     SEQUENCE {
 *   28  257:       INTEGER
 *          :         00 A4 C2 86 6D FE 96 17 24 90 7F 70 BC FF 35 50
 *          :         84 A6 C2 88 06 04 0A 79 6F 30 C9 ED 45 93 B7 51
 *          :         91 6B 45 E8 70 4A C3 4C 52 B9 11 AD 94 72 8A 24
 *          :         6D 6C 6E 5A 66 D7 F6 CF 17 28 8B 90 22 55 CD 45
 *          :         AA DC 37 00 1B 44 D2 91 EE 4D DB 43 B4 83 C2 E7
 *          :         7F BC 94 C4 CF 27 24 6B 9D 26 5D A7 FD 31 65 D2
 *          :         0C FC 6C F4 34 F9 05 D6 EC 96 B3 7F 45 B4 90 BB
 *          :         15 8A 26 CE B5 3E A5 3D 41 8E 0E 0D 26 F2 79 A6
 *          :                 [ Another 129 bytes skipped ]
 *  289    3:       INTEGER 65537
 *          :       }
 *          :     }
 *          :   }
 *  
 */
void expect(bool tested, const std::string& msg)
{
    if (!tested) throw(CertificateException(msg));
}

std::string readFile(const char *fname)
{
    std::ifstream ifs(fname, std::ios_base::binary);
    std::string contents((std::istreambuf_iterator<char>(ifs)), 
                         std::istreambuf_iterator<char>());
    
    return contents;
}

int main(int argc, char **argv)
{
    try {
        std::string certStr = readFile("torproject.der");
        std::string expectedSpki = readFile("spki.der");

        Certificate cert(certStr);
        std::string spki = cert.selectorData(TLSAjs::SPKI);

        expect(expectedSpki == spki, "Wrong SPKI was parsed");
        expect(bin2hex(cert.matchingData(TLSAjs::SHA256, TLSAjs::FULL)) ==
               "23b854af6b96c0224fd173382c520b465a94f2d4e7238893f63ad2d783e27b4b", 
               "Wrong SHA256 for full cert");
        expect(bin2hex(cert.matchingData(TLSAjs::SHA512, TLSAjs::FULL)) ==
               "9cb4f24a3515cb198696dd4f33aa4de6f0005a9c43afc86482ca54a0e2f558fae9ddd8eec1880f4e2b05401e506f6d60455493a0904b2cb1ef172081467614e9", 
               "Wrong SHA512 for full cert");
        expect(bin2hex(cert.matchingData(TLSAjs::SHA256, TLSAjs::SPKI)) ==
               "a01bfa93ecac24481618e4c589e9ec0ffbe34c416a0eb5f77a387dd9657dbb45", 
               "Wrong SHA256 for SPKI");
        expect(bin2hex(cert.matchingData(TLSAjs::SHA512, TLSAjs::SPKI)) ==
               "a9cd977cd8c71d591730352b1ec8f3f860c288b4bb95393b6cd6e4aeb249f8b260912c71b9df02e176ee4132f503a70c1ff3a4891d31f8caebf1c91541d819ce", 
               "Wrong SHA512 for SPKI");
    }
    catch (const std::exception& e) {
        cout << e.what() << endl;
        return 1;
    }
    
    cout << "Certificate test passed" << endl;
    return 0;

    // Valgrind shows about 500 bytes from internal openssl structs still 
    // reachable at the end, but the count doesn't grow if test body is 
    // repeated in cycle.
}
