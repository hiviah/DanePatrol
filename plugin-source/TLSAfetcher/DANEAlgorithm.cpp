/*! 
 * @file DANEAlgorithm.cpp
 * @brief Implementation for DANE TLSA check
 *
 */
 
#include <cstring>
#include <cassert>
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
            throw CertificateException("Failed to parse certificate");
    }

    boost::shared_ptr<EVP_PKEY> pubkey(X509_get_pubkey(sslCert.get()), EVP_PKEY_free);

    if (!pubkey.get()) {
            throw CertificateException("Failed to get SPKI of certificate");
    }

    int pkeyLen;
    pkeyLen = i2d_PUBKEY(pubkey.get(), NULL);
    boost::scoped_array<char> pubkeyBuf(new char[pkeyLen]);
    unsigned char* pubkeyBufptr = (unsigned char*)pubkeyBuf.get();
    i2d_PUBKEY(pubkey.get(), &pubkeyBufptr);

    std::string pubkeyStr(pubkeyBuf.get(), pkeyLen);
    return pubkeyStr;
}

std::string Certificate::opensslDigest(const EVP_MD *md, const std::string &data)
{
    EVP_MD_CTX mdctx;
    unsigned int md_len;
    unsigned char md_value[64]; // enough bytes for SHA2 family up to SHA-512
    std::string digest;
    
    assert(md);
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, data.data(), data.size());
    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);
    
    digest = std::string((char *)md_value, md_len);
    return digest;
}

std::string Certificate::sha256(const std::string &data)
{
    return opensslDigest(EVP_sha256(), data);
}

std::string Certificate::sha512(const std::string &data)
{
    return opensslDigest(EVP_sha512(), data);
}

std::string Certificate::selectorData(TLSAjs::Selector selector) const
{
    switch (selector) {
        case TLSAjs::FULL:
            return m_derData;
        case TLSAjs::SPKI:
            return spki();
        default:
            throw DANEException("Unknown selector type");
    };
}

std::string Certificate::matchingData(TLSAjs::MatchingType matching, TLSAjs::Selector selector) const
{
    std::string data = selectorData(selector);
    
    switch (matching) {
        case TLSAjs::EXACT:
            return data;
        case TLSAjs::SHA256:
            return sha256(data);
        case TLSAjs::SHA512:
            return sha512(data);
        default:
            break;
    };
}

