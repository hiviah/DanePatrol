/*! 
 * @file TLSAfetcherAPI.cpp
 * @brief Objects facing JSAPI interface, visible from Javascript in addon
 *
 */
 

#include "JSObject.h"
#include "DOM/Document.h"
#include "global/config.h"

#include <string>
#include "boost/format.hpp"

#include "variant.h"
#include "variant_list.h"
#include "variant_map.h"
#include "TLSAfetcherAPI.h"

ResolverException::ResolverException(const ResolverException& other) throw()
{
    m_message = other.m_message;
}

ResolverException& ResolverException::operator= (const ResolverException& other) throw()
{
	if (this == &other) return *this;
	
	m_message = other.m_message;
	
	return *this;
}

TLSAfetcherAPI::TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host) : 
	m_plugin(plugin), 
	m_host(host),
	m_resolver()
{
    registerMethod("fetchTLSA", make_method(this, &TLSAfetcherAPI::fetchTLSA));

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &TLSAfetcherAPI::get_version));
    
}

TLSAfetcherAPI::~TLSAfetcherAPI()
{
}

TLSAfetcherPtr TLSAfetcherAPI::getPlugin()
{
    TLSAfetcherPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}


// Read-only property version
std::string TLSAfetcherAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}

FB::variant TLSAfetcherAPI::fetchTLSA(const std::string& fqdn, int port)
{
    return m_resolver.fetchTLSA(fqdn, port).toVariant();
}

