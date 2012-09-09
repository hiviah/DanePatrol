/**********************************************************\

  Auto-generated TLSAfetcherAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "DOM/Document.h"
#include "global/config.h"

#include <string>
#include "boost/format.hpp"

#include "variant.h"
#include "variant_list.h"
#include "variant_map.h"
#include "TLSAfetcherAPI.h"

#include "ldns/ldns.h"
#include "unbound.h"

#define RR_TYPE_TLSA (ldns_rr_type(52))

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

ResolvedTLSA::ResolvedTLSA(uint8_t certUsage, uint8_t selector, uint8_t matchingType, std::string association):
    m_certUsage(certUsage),
    m_selector(selector),
    m_matchingType(matchingType),
    m_association(association)
{
}

FB::VariantMap ResolvedTLSA::toJSVariant() const
{
    #define keyname(x) std::string(x)
    FB::VariantMap result = FB::variant_map_of(keyname("certUsage"), m_certUsage);
    result[keyname("selector")] = m_selector;
    result[keyname("matchingType")] = m_matchingType;
    result[keyname("association")] = m_association;
    #undef keyname
    
    return result;
}

TLSAfetcherAPI::TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host) : 
	m_plugin(plugin), 
	m_host(host),
	m_resolver(NULL)
{
    registerMethod("fetchTLSA", make_method(this, &TLSAfetcherAPI::fetchTLSA));

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &TLSAfetcherAPI::get_version));
    
    try {
    	initializeUnbound();
    }
    catch (const ResolverException& e) {
    	FBLOG_FATAL("", e.message());
    	
    	if (m_resolver) {
	    ub_ctx_delete(m_resolver);
	    m_resolver = NULL;
    	}
    }
}

void TLSAfetcherAPI::initializeUnbound()
{
    // Unbound initialization
    int ub_retval;

    m_resolver = ub_ctx_create();

    if (!m_resolver) {
        throw ResolverException("Failed to create ub_ctx resolver");
    }
    
    ub_retval = ub_ctx_add_ta(m_resolver, const_cast<char*>(m_rootTrustAnchor));
    if (ub_retval != 0) {
        boost::format fmt("Cannot add trust anchor to resolver: %1%)");
        fmt % std::string(ub_strerror(ub_retval));
        throw ResolverException(fmt.str());
    }
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

TLSAList TLSAfetcherAPI::parseResult(const ub_result* result) const
{
    ldns_pkt *packet=NULL;
    ldns_rr_list *rrs = NULL;
    ldns_status parse_status = ldns_wire2pkt(&packet, (uint8_t*)(result->answer_packet), result->answer_len);
    TLSAList tlsaList;
    
    if (!result->havedata) {
	return tlsaList;
    }
    
    try {
	if (parse_status != LDNS_STATUS_OK) {
		throw ResolverException("Failed to parse response packet\n");
	}
	
	rrs = ldns_pkt_rr_list_by_type(packet, RR_TYPE_TLSA, LDNS_SECTION_ANSWER);
	for (int i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
	    /* extract first rdf, which is the whole TLSA record */
	    ldns_rr *rr = ldns_rr_list_rr(rrs, i);
	    if (ldns_rr_rd_count(rr) < 1) {
		FBLOG_WARN("", "RR has no RDFs\n");
		ldns_rr_free(rr);
		continue;
	    }
    
	    ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
	    
	    size_t rdf_size = ldns_rdf_size(rdf);
	    if (rdf_size < 4) {
		FBLOG_WARN("", "TLSA record in RR too short\n");
		ldns_rr_free(rr);
		continue;
	    }
    
	    uint8_t cert_usage, selector, matching_type;
	    uint8_t *rdf_data = ldns_rdf_data(rdf);
	    std::string association;
    
	    cert_usage = rdf_data[0];
	    selector = rdf_data[1];
	    matching_type = rdf_data[2];
	    
	    for (int j=3; j<rdf_size; j++) {
		association += (boost::format("%1$02x") % int(rdf_data[j])).str();
	    }
	    
	    tlsaList.push_back(ResolvedTLSA(cert_usage, selector, matching_type, association).toJSVariant());
	    
	    ldns_rr_free(rr);
	}
    }
    catch (const ResolverException &e) {
    	FBLOG_WARN("", e.message());
    }
    
    if (packet)  ldns_pkt_free(packet);
    if (rrs) ldns_rr_list_free(rrs);
    
    return tlsaList;
}

FB::VariantMap TLSAfetcherAPI::fetchTLSA(const std::string& fqdn, int port)
{
    struct ub_result *resolveResult;
    TLSAList tlsaList;
    FB::VariantMap jsResult;
    int retval, rcode;

    if (!canResolve()) {
    	return FB::variant_map_of(std::string("result"), -2);
    }
    
    if (port < 1 || port > 0xffff || fqdn.size() < 1) {
        return FB::variant_map_of(std::string("result"), -1);
    }

    boost::format fmt("_%2%._tcp.%1%");
    fmt % fqdn % port;
    std::string rrName = fmt.str();

    retval = ub_resolve(m_resolver, const_cast<char *>(rrName.c_str()), 
        RR_TYPE_TLSA, LDNS_RR_CLASS_IN, &resolveResult);

    if (retval == 0) {
    	tlsaList = parseResult(resolveResult);
    }
    
    rcode = resolveResult->rcode;
    ub_resolve_free(resolveResult);
    
    std::string dnssecStatus;
    if (resolveResult->secure) {
    	dnssecStatus = "secure";
    } else if (resolveResult->bogus) {
    	dnssecStatus = "bogus";
    } else {
    	dnssecStatus = "insecure";
    }
    
    jsResult["result"] = retval;
    jsResult["rcode"] = rcode;
    jsResult["tlsa"] = tlsaList;
    jsResult["dnssec"] = dnssecStatus;
    
    return jsResult;
}


const char *TLSAfetcherAPI::m_rootTrustAnchor(
    ".   IN DS   19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5");
