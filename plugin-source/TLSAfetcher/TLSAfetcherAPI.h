/**********************************************************\

  Auto-generated TLSAfetcherAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "TLSAfetcher.h"

#ifndef H_TLSAfetcherAPI
#define H_TLSAfetcherAPI

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
    
    // Event helpers
    FB_JSAPI_EVENT(fired, 3, (const FB::variant&, bool, int));
    FB_JSAPI_EVENT(echo, 2, (const FB::variant&, const int));
    FB_JSAPI_EVENT(notify, 0, ());

    // Method test-event
    void testEvent(const FB::variant& s);

private:
    TLSAfetcherWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    std::string m_testString;
};

#endif // H_TLSAfetcherAPI

