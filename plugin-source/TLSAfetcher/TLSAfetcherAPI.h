/**********************************************************\

  Auto-generated TLSAfetcherAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <stdexcept>

#include "boost/weak_ptr.hpp"


#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "variant_map.h"
#include "variant.h"
#include "TLSAfetcher.h"

#include "JSAPI_IDL/TLSAfetcherStructures.h"

#ifndef H_TLSAfetcherAPI
#define H_TLSAfetcherAPI

struct ub_ctx;
struct ub_result;

/*! Exception for signaling resolving or DNS parsing errors. */
class ResolverException
{
public:

    ResolverException(const char  *msg) throw():
    	m_message(msg) {}
    ResolverException(const std::string& msg) throw():
    	m_message(msg) {}
    		
    const std::string& message() const
    	{return m_message;}
    
    ResolverException(const ResolverException& other) throw();
    ResolverException& operator= (const ResolverException& other) throw();

protected:

    std::string m_message;
};

/*! Container for parsed TLSA RR */
typedef JSAPI::ResolvedTLSA ResolvedTLSA;

/*! List of parsed TLSA records represented as JSAPI-compatible list */
typedef FB::VariantList TLSAList;

class TLSAfetcherAPI : public FB::JSAPIAuto
{
public:

	/*!
	 * Constructor for the JSAPI object. JSAPI methods available from browser 
	 * javascript are registered here.
	 *
	 *  @see FB::JSAPIAuto::registerMethod
	 *  @see FB::JSAPIAuto::registerProperty
	 *  @see FB::JSAPIAuto::registerEvent
	 */
    TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host);
    
  /*!
   * Destructor.  Remember that this object will not be released until
   * the browser is done with it; this will almost definitely be after
   * the plugin is released.
   */
    virtual ~TLSAfetcherAPI();

    /*! 
     * Gets a reference to the plugin that was passed in when the object
     * was created.  If the plugin has already been released then this
     * will throw a FB::script_error that will be translated into a
     * javascript exception in the page.
	 */
    TLSAfetcherPtr getPlugin();

    /*! Returns version string. Bound to JSAPI "version" property. */
    std::string get_version();

    /*! 
     * Fetch TLSA records. Protocol for the queried TLSA is always TCP.
     * 
     * Returned as variant map passable to JSAPI. Exposed JSAPI method.
     *
     * @param fqdn: FQDN of host whose TLS certificates to query 
     *				(without _port._proto prefix)
     * @param port: port of the TLS service
     */
    FB::VariantMap fetchTLSA(const std::string& fqdn, int port);
    
    /*! Whether the resolver is usable. */
    bool canResolve() const
    	{return m_resolver != NULL;}

private:

    /*! 
     * Initialize unbound resolver context.
     *
     * @throws ResolverException on error
     */
    void initializeUnbound();
    
    /*!
     * Parse result from unbound resolver into list of JSAPI TLSA structures.
     *
     * @param result: result from ub_resolve
     */
    TLSAList parseResult(const ub_result* result) const;
    
    /*! Weak pointer to JS root plugin */
    TLSAfetcherWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    std::string m_testString;
    
    /*! Builtin DS record for root DNS zone */
    static const char *m_rootTrustAnchor;

    /*! libunbound resolver context - is thread safe */
    ub_ctx *m_resolver;
    
};

#endif // H_TLSAfetcherAPI

