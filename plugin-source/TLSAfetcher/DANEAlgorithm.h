/*! 
 * @file DANEAlgorithm.h
 * @brief Interface for DANE algorithm from RFC 6698
 *
 */
 
#ifndef H_DANEAlgorithm
#define H_DANEAlgorithm

#include <string>
#include <vector>

class Certificate
{
public:

    /*! Construct certificate from DER-encoded data. */
    Certificate(const std::string& derData);

    /*! Return cert as DER-encoded */
    const std::string& asDer() const
        { return m_derData; }

    /*! Return ASN.1 DER-encoded SubjectPublicKeyInfo structure. */
    const std::string& spki() const
        { return m_spki; }

protected:

    /*! DER-encoded cert */
    std::string m_derData;

    /*! DER-encoded ASN.1 structure of SPKI. */
    std::string m_spki;
};

/*! Typedef for certificate chain. */
typedef std::vector<Certificate> CertChain;

/*! Implementation of DANE/TLSA checking algorithm for a site. */
class DANEAlgorithm
{
public:

protected:

    /*! Certificate chain of site to be checked. */
    CertChain m_certChain;
};

#endif /* H_DANEAlgorithm */
