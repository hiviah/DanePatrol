/*! 
 * @file DANEAlgorithm.h
 * @brief Interface for DANE algorithm from RFC 6698
 *
 */
 
#ifndef H_DANEAlgorithm
#define H_DANEAlgorithm

#include <string>
#include <vector>

#include "Resolver.h"
#include "Exceptions.h"
#include "openssl/evp.h"


class Certificate
{
public:

    /*! Construct certificate from DER-encoded data. */
    Certificate(const std::string& derData);

    /*! Return cert as DER-encoded */
    const std::string& asDer() const
        { return m_derData; }

    /*! Return cert as PEM-encoded */
    std::string asPem() const;

    /*!
     * Return ASN.1 DER-encoded SubjectPublicKeyInfo structure.
     *
     * @throws CertificateException: if certificate parsing fails
     */
    std::string spki() const;
    
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

    /*! 
     * Compute digest of data using openssl algorithm, in binary.
     * 
     * @param md: openssl message digest object that specifies the algorithm
     * @param data: data to compute upon
     */
    static std::string opensslDigest(const EVP_MD *md, const std::string& data);
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
    
    /*! 
     * Initialize DANE TLSA checking for TLS with specified certificate chain.
     *
     * @throws DANEException: if arguments are invalid (e.g. empty chain)
     */
    DANEAlgorithm(const CertChain certChain);
    
    /*! 
     * Check TLSA records and try to match them against certificate chain.
     *
     * @param lookup: result of TLSA lookup from resolver
     * @param policy: bitmap of DANEPolicy which certificate usage is allowed
     */
    DANEMatch check(const TLSALookupResult& lookup, int policy) const;
    
    /*! Check whether given TLSA matches EE cert of the chain.
     *
     * @throws DANEException: if selector or matching type is unknown
     * @returns index of cert in chain that matched (0) or -1 if no match
     */ 
    int eeCertMatch(const ResolvedTLSA& tlsa) const;

    /*! Check whether given TLSA matches CA cert of the chain.
     *
     * @throws DANEException: if selector or matching type is unknown
     * @returns index of cert in chain that matched [1..n] or -1 if no match
     */ 
    int caCertMatch(const ResolvedTLSA& tlsa) const;

    /*! Check whether given TLSA matches any cert in the chain.
     *
     * @throws DANEException: if selector or matching type is unknown
     * @returns index of cert in chain that matched [1..n] or -1 if no match
     */ 
    int chainCertMatch(const ResolvedTLSA& tlsa) const;

protected:

    
    /*! Return a list of TLSA record where only those matching policy remain */ 
    static TLSAList policyFilter(const TLSAList& tlsaList, int policy);
    
    /*! Certificate chain of site to be checked. */
    CertChain m_certChain;
    
};

#endif /* H_DANEAlgorithm */
