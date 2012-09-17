/*! 
 * @file DANEAlgorithm.cpp
 * @brief Implementation for DANE TLSA check
 *
 */
 
#include <cstring>
#include <boost/scoped_array.hpp>
#include <boost/shared_ptr.hpp>

#include "openssl/x509.h"
#include "openssl/evp.h"

#include "DANEAlgorithm.h"

Certificate::Certificate(const std::string &derData):
    m_derData(derData)
{
}

std::string Certificate::spki() const
{
    int len = m_derData.size();
    boost::scoped_array<unsigned char> buf(new unsigned char[len]);
    unsigned char *bufptr = buf.get();

    memcpy(bufptr, m_derData.data(), len);

    boost::shared_ptr<X509> sslCert(d2i_X509(NULL, const_cast<const unsigned char**>(&bufptr), len), X509_free);
    if (!sslCert.get()) {
            throw CertificateError("Failed to parse certificate");
    }

    boost::shared_ptr<EVP_PKEY> pubkey(X509_get_pubkey(sslCert.get()), EVP_PKEY_free);

    if (!pubkey.get()) {
            throw CertificateError("Failed to get SPKI of certificate");
    }

    int pkeyLen;
    pkeyLen = i2d_PublicKey(pubkey.get(), NULL);
    boost::scoped_array<char> pubkeyBuf(new char[pkeyLen]);
    unsigned char* pubkeyBufptr = (unsigned char*)pubkeyBuf.get();
    i2d_PublicKey(pubkey.get(), &pubkeyBufptr);

    std::string pubkeyStr(pubkeyBuf.get(), pkeyLen);
    return pubkeyStr;
}
