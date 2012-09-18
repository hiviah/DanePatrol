/*! 
 * @file DANEAlgorithm.h
 * @brief Interface for DANE algorithm from RFC 6698
 *
 */
 
#ifndef H_DANEAlgorithm
#define H_DANEAlgorithm

#include <string>
#include <vector>

#include "JSAPI_IDL/TLSAfetcherStructures.h"
#include "Exceptions.h"

class Certificate
{
public:

    /*! Construct certificate from DER-encoded data. */
    Certificate(const std::string& derData);

    /*! Return cert as DER-encoded */
    const std::string& asDer() const
        { return m_derData; }

    /*!
     * Return ASN.1 DER-encoded SubjectPublicKeyInfo structure.
     *
     * @throws CertificateException: if certificate parsing fails
     */
    std::string spki() const;
    
    /*! Return named digest of data using openssl algorithms, in binary. */
    static std::string opensslDigest(const char *name, const std::string& data);
    
    /*! Returns SHA256 of data, in binary. */
    static std::string sha256(const std::string& data);
    
    /*! Returns SHA512 of data, in binary. */
    static std::string sha512(const std::string& data);
    
    /*! 
     * Returns data that are to be matched according to selector.
     * 
     * @throws DANEException: if selector is unknown
     */ 
    std::string selectorData(TLSAjs::Selector selector) const;
    
    /*! 
     * Returns data that are to be matched according to matching type and
     * selector combination.
     * 
     * @throws DANEException: if selector or matching type is unknown
     */
    std::string matchingData(TLSAjs::MatchingType matching, 
                             TLSAjs::Selector selector) const;

protected:

    /*! DER-encoded cert */
    std::string m_derData;
};

/*! Typedef for certificate chain. First cert is the EE cert. */
typedef std::vector<Certificate> CertChain;

typedef TLSAjs::DANEMatch DANEMatch;

/*! Implementation of DANE/TLSA checking algorithm for a site. */
class DANEAlgorithm
{
public:
    
    DANEAlgorithm(const std::string host, int port, const CertChain certChain);
    
    /*! Resolve TLSA records and try to match them against certificate chain */
    DANEMatch resolveAndCheck();

protected:

    /*! Certificate chain of site to be checked. */
    CertChain m_certChain;
};

#endif /* H_DANEAlgorithm */
