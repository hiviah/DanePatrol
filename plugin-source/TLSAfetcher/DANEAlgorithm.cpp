/*! 
 * @file DANEAlgorithm.cpp
 * @brief Implementation for DANE TLSA check
 *
 */
 
#include <cstring>
#include <cassert>
#include <sstream>
#include <algorithm>

#include "boost/scoped_array.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/archive/iterators/base64_from_binary.hpp"
#include "boost/archive/iterators/insert_linebreaks.hpp"
#include "boost/archive/iterators/transform_width.hpp"
#include "boost/archive/iterators/ostream_iterator.hpp"

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
            throw DANEException("Unknown matching type");
    };
}

std::string Certificate::asPem() const
{
    // well, this is ugly
    using namespace boost::archive::iterators;

    size_t paddedChars = (3-(m_derData.size()%3))%3;

    std::stringstream os;
    os << "-----BEGIN CERTIFICATE-----\n";

    typedef
        insert_linebreaks<         // insert line breaks every 64 characters
            base64_from_binary<    // convert binary values ot base64 characters
                transform_width<   // retrieve 6 bit integers from a sequence of 8 bit bytes
                    const char *,
                    6,
                    8
                >
            >
            ,64
        >
        base64_text; // compose all the above operations in to a new iterator

    std::copy(
        base64_text(m_derData.data()),
        base64_text(m_derData.data() + m_derData.size()),
        ostream_iterator<char>(os)
    );

    os << std::string(paddedChars, '=');
    os << "\n-----END CERTIFICATE-----\n";
    return os.str();
}

DANEAlgorithm::DANEAlgorithm(const CertChain certChain):
    m_certChain(certChain)
{
    if (m_certChain.size() < 1) {
        throw DANEException("Empty chain passed to DANE checking");
    }
}

TLSAList DANEAlgorithm::policyFilter(const TLSAList& tlsaList, int policy)
{
    TLSAList filteredTLSA;
    TLSAList::const_iterator it = tlsaList.begin();
    
    for ( ; it != tlsaList.end(); it++) {
        switch (it->certUsage) {
            case TLSAjs::CA_CERT_PIN:
            case TLSAjs::EE_CERT_PIN:
                if (policy & TLSAjs::ALLOW_TYPE_01) {
                    filteredTLSA.push_back(*it);
                }
                break;
            case TLSAjs::CA_TA_ADDED:
            case TLSAjs::EE_TA_ADDED:
                if (policy & TLSAjs::ALLOW_TYPE_23) {
                    filteredTLSA.push_back(*it);
                }
                break;
            default:
                break;
        };
    }
    
    return filteredTLSA;
}
        
DANEMatch DANEAlgorithm::check(const TLSALookupResult &lookup, int policy) const
{
    DANEMatch match;
    match.successful = false;
    match.abort = false;
    
    // TODO: How would libunbound react if some TLSA were signed and others not?
    // Guessing whole thing would be marked bogus, thus we can't filter just
    // TLSA RRs with correct signature.
    switch (lookup.dnssecStatus) {
        case TLSAjs::INSECURE:
            return match;
        case TLSAjs::BOGUS:
            match.abort = true;
            match.errorStr = "TLSA query returned with bogus DNSSEC signature";
            return match;
        case TLSAjs::SECURE:
            break; // continue checking
    }
    
    TLSAList filteredTLSA = policyFilter(lookup.tlsa, policy);
    TLSAList::const_iterator it;
    // per section 4.1 of RFC 6698
    size_t usableAssociationCount = filteredTLSA.size();
    
    for (it = filteredTLSA.begin() ; it != filteredTLSA.end(); it++) {
        try {
            // TLSA RRs are already filtered by policy, we can group them
            int idx = -1;
            switch (it->certUsage) {
                case TLSAjs::CA_CERT_PIN:
                    idx = caCertMatch(*it);
                    break;
                // cert usage 2 is supposed to be used for CA certs, but can
                // match any cert in chain by specification
                case TLSAjs::CA_TA_ADDED:
                    idx = chainCertMatch(*it);
                    break;
                case TLSAjs::EE_CERT_PIN:
                case TLSAjs::EE_TA_ADDED:
                    idx = eeCertMatch(*it);
                    break;
                default:
                    break; // unknown cert usage, skip
            };
            
            // if we have a match, copy cert and TLSA into the result
            if (idx >= 0) {
                match.successful = true;
                match.abort = false;
                match.derCert = m_certChain[idx].asDer();
                match.pemCert = m_certChain[idx].asPem();
                match.tlsa = *it;
                return match;
            }
        }
        catch (const DANEException& e) {
            // unknown matching type or selector, skip as unusable
            usableAssociationCount--;
        }
    }
    
    // We had nonzero usable associations, none succeeded => hard fail 
    if (usableAssociationCount > 0) {
        match.abort = true;
        match.errorStr = "None of nonzero usable TLSA associations matched.";
    } else {
        match.errorStr = "No usable TLSA associations.";
    }
    
    return match;
}

int DANEAlgorithm::eeCertMatch(const ResolvedTLSA &tlsa) const
{
    try {
        if (m_certChain.front().matchingData(tlsa.matchingType, tlsa.selector) == tlsa.association) {
            return 0; //index 0 - the EE cert - matched
        }
    }
    catch (const CertificateException& ) {
        return -1; // cert parsing failed
    }
    
    return -1;
}

int DANEAlgorithm::caCertMatch(const ResolvedTLSA &tlsa) const
{
    for (int i = 1; i < m_certChain.size(); i++) {
        try {
            if (m_certChain[i].matchingData(tlsa.matchingType, tlsa.selector) == tlsa.association) {
                return i;
            }
        }
        catch (const CertificateException& ) {
            continue; // cert parsing failed
        }
    }
    
    return -1;
}

int DANEAlgorithm::chainCertMatch(const ResolvedTLSA &tlsa) const
{
    for (int i = 0; i < m_certChain.size(); i++) {
        try {
            if (m_certChain[i].matchingData(tlsa.matchingType, tlsa.selector) == tlsa.association) {
                return i;
            }
        }
        catch (const CertificateException& ) {
            continue; // cert parsing failed
        }
    }
    
    return -1;
}


