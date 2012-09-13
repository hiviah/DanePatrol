/*! 
 * @file TLSAfetcherAPI.h
 * @brief Interface defining methods and classes visible in Javascript
 *
 */
 

#ifndef H_TLSAfetcherAPI
#define H_TLSAfetcherAPI

#include <string>

#include "boost/weak_ptr.hpp"

#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "variant_map.h"
#include "variant.h"

#include "TLSAfetcher.h"
#include "Resolver.h"

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
     * Fetch TLSA records, by delegating request to Resolver.
     * Exposed JSAPI method.
     * 
     * @param fqdn: FQDN of host whose TLS certificates to query 
     *				(without _port._proto prefix)
     * @param port: port of the TLS service
     * @returns: variant map passable to JSAPI
     */
    FB::variant fetchTLSA(const std::string& fqdn, int port);
    
    /*! Whether the resolver is usable. */
    bool canResolve() const
    	{return m_resolver.canResolve();}

private:

    /*! Weak pointer to JS root plugin */
    TLSAfetcherWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
    
    /*! DNS resolver - wrapped unbound */
    Resolver m_resolver;

};

#endif // H_TLSAfetcherAPI

