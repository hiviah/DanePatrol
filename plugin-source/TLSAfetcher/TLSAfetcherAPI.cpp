/*!
 * @file TLSAfetcherAPI.cpp
 * @brief Objects facing JSAPI interface, visible from Javascript in addon
 *
 */
 

#include "JSObject.h"
#include "DOM/Document.h"
#include "global/config.h"

#include <string>
#include <algorithm>
#include <iterator>
#include "boost/format.hpp"
#include "boost/lambda/lambda.hpp"
#include "boost/lambda/bind.hpp"
#include "boost/lambda/construct.hpp"
#include "boost/regex.hpp"

#include "variant.h"
#include "variant_list.h"
#include "variant_map.h"
#include "TLSAfetcherAPI.h"
#include "DANEAlgorithm.h"

using namespace boost::lambda;

TLSAfetcherAPI::TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host) : 
	m_plugin(plugin), 
	m_host(host),
	m_resolver()
{
    registerMethod("fetchTLSA", make_method(this, &TLSAfetcherAPI::fetchTLSA));
    registerMethod("checkDANE", make_method(this, &TLSAfetcherAPI::checkDANE));

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

bool TLSAfetcherAPI::looksLikeFQDN(const std::string &fqdn)
{
    // not exhaustive, but should severely limit "fuzzing" of unbound
    boost::regex fqdnRe("(?:[a-zA-Z0-9-]+\\.)*[a-zA-Z0-9-]+\\.?");

    return boost::regex_match(fqdn, fqdnRe);
}

FB::variant TLSAfetcherAPI::fetchTLSA(const std::string& fqdn, int port)
{
    return m_resolver.fetchTLSA(fqdn, port).toVariant();
}

FB::variant TLSAfetcherAPI::checkDANE(const std::string &fqdn, int port,
                                      const std::vector<std::string> &certList,
                                      int policy)
{
    CertChain chain;
    TLSALookupResult lookup;
    DANEMatch match;

    lookup.result = -1;

    try {
        if (!looksLikeFQDN(fqdn)) {
            throw DANEException("FQDN looks sketchy, not resolving TLSA");
        }

        lookup = m_resolver.fetchTLSA(fqdn, port);

        // convert hex DER cert strings into CertChain
        std::transform(certList.begin(), certList.end(), std::back_inserter(chain),
                       bind(constructor<Certificate>(),
                            bind(hex2bin, ::boost::lambda::_1)));

        DANEAlgorithm algo(chain);
        match = algo.check(lookup, policy);
    }
    catch (const TLSAfetcherException& ) {
        match.successful = false;
    }

    return match.toVariant();
}
