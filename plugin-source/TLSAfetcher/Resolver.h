/*! 
 * @file Resolver.h
 * @brief Wrapper for C-style unbound API
 *
 */
 
#ifndef H_Resolver
#define H_Resolver

#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>

#include "variant.h"

#include "ldns/rr.h"
#include "JSAPI_IDL/TLSAfetcherStructures.h"
#include "Exceptions.h"

struct ub_ctx;
struct ub_result;

std::string bin2hex(const std::string& val);

std::string hex2bin(const std::string& val);

/*! Container for parsed DNS lookup result with TLSA RRs */
typedef TLSAjs::ResolvedTLSA ResolvedTLSA;

/*! Container for parsed DNS lookup result with TLSA RRs */
typedef TLSAjs::TLSALookupResult TLSALookupResult;

/*! List of parsed TLSA records represented as JSAPI-compatible list */
typedef std::vector<ResolvedTLSA> TLSAList;
    
/*! Shared pointer around ub_ctx */
typedef boost::shared_ptr<ub_ctx> UbCtx;


/*! C++ interface to unbound resolver ub_ctx. */
class Resolver
{
public:

    /*! 
     * Initialize unbound resolver context.
     *
     * @param trustAnchors: if non-empty, content will override builtin DS for 
     * root zone.
     * @throws ResolverException on error
     */
    Resolver(const std::string& trustAnchors = "");

    virtual ~Resolver();
    
    bool canResolve() const 
        {return m_canResolve;}
    
    /*! TLSA RR type not yet defined in ldns */
    static const ldns_rr_type RR_TYPE_TLSA = ldns_rr_type(52);

    /*! 
     * Fetch TLSA records. Protocol for the queried TLSA is always TCP.
     *
     * @param fqdn: FQDN of host whose TLS certificates to query 
     *				(without _port._proto prefix)
     * @param port: port of the TLS service
     */
    TLSALookupResult fetchTLSA(const std::string& fqdn, int port);
    
protected:
    
    /*!
     * Parse result from unbound resolver into list of JSAPI TLSA structures.
     *
     * @param result: result from ub_resolve
     * @throws ResolverException: if packet is malformed
     */
    TLSAList parseResult(const ub_result* result) const;
    
    /*!
     * Setup unbound context with trust anchors, etc.
     *
     * @throws ResolverException on error
     */
    void initializeResolver(const std::string& trustAnchors = "");
    
    /*! Builtin DS record for root DNS zone */
    static const std::string m_rootTrustAnchor;

    /*! Builtin DLV key */
    static const std::string m_dlvTrustAnchor;

    /*! libunbound resolver context - is thread safe */
    UbCtx m_resolver;

   /*! Signifies whether unbound resolver was successfully initialized. */
    bool m_canResolve;
    
};


#endif /* H_Resolver */
