#include <string>
#include <iostream>
#include <fstream>
#include <iterator>

#include "Resolver.h"
#include "DANEAlgorithm.h"

using std::cout;
using std::endl;

void expect(bool tested, const std::string& msg)
{
    if (!tested) throw(CertificateError(msg));
}

int main(int argc, char **argv)
{
    try {
        std::ifstream ifs("torproject.der", std::ios_base::binary);
        std::string certStr((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

        cout << "Cert len: " << certStr.size() << endl;

        Certificate cert(certStr);
        std::string spki = cert.spki();

        cout << "SPKI len: " << spki.size() << endl;
        cout << bin2hex(spki) << endl;
    }
    catch (const std::exception& e) {
        cout << e.what() << endl;
        return 1;
    }

    cout << "Certificate test passed" << endl;
    return 0;
}
