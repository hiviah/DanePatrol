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
#include "TLSAfetcher.h"

#ifndef H_TLSAfetcherAPI
#define H_TLSAfetcherAPI

struct ub_ctx;
struct ub_result;

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

struct ResolvedTLSA
{
    ResolvedTLSA(uint8_t certUsage, uint8_t selector, uint8_t matchingType, std::string association);
    
    FB::VariantMap toJSVariant() const;
    
    uint8_t m_certUsage;
    uint8_t m_selector;
    uint8_t m_matchingType;
    
    std::string m_association;
};

typedef FB::VariantList TLSAList;

class TLSAfetcherAPI : public FB::JSAPIAuto
{
public:
    TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host);
    virtual ~TLSAfetcherAPI();

    TLSAfetcherPtr getPlugin();

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

    // Read-only property ${PROPERTY.ident}
    std::string get_version();

    // Method echo
    FB::variant echo(const FB::variant& msg);

    /*! Fetch TLSA records.
     */
    FB::VariantMap fetchTLSA(const std::string& fqdn, int port);
    
    // Event helpers
    FB_JSAPI_EVENT(fired, 3, (const FB::variant&, bool, int));
    FB_JSAPI_EVENT(echo, 2, (const FB::variant&, const int));
    FB_JSAPI_EVENT(notify, 0, ());

    // Method test-event
    void testEvent(const FB::variant& s);
    
    bool canResolve() const
    	{return m_resolver != NULL;}

private:

    void initializeUnbound();
    TLSAList parseResult(const ub_result* result) const;
    
    TLSAfetcherWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    std::string m_testString;
    
    /*! Builtin DS record for root DNS zone */
    static const char *m_rootTrustAnchor;

    /*! libunbound resolver context - is thread safe */
    ub_ctx *m_resolver;
    
};

#endif // H_TLSAfetcherAPI

