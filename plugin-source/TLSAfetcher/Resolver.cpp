/*! 
 * @file Resolver.cpp
 * @brief Wrapper for C-style unbound API
 *
 */
 
#include <boost/format.hpp>
#include <boost/scoped_ptr.hpp>
#include <string>
#include <sstream>
#include <iterator>
#include <stdexcept>

#include "logging.h"

#include "Resolver.h"
#include "ldns/ldns.h"
#include "unbound.h"


using TLSAjs::CertUsage;
using TLSAjs::MatchingType;
using TLSAjs::Selector;
using TLSAjs::DNSSECStatus;

// ...never thought I'd write bin2hex again
// I mean ... really? There must be an elegant way
std::string bin2hex(const std::string& val)
{
    std::string res;
    std::string::const_iterator it = val.begin();

    for ( ; it != val.end(); it++) {
	int v = uint8_t(*it);
	std::string vs = (boost::format("%1$02x") % v).str();
	res += vs;
    }

    return res;	    
}

std::string hex2bin(const std::string& val)
{
    if (val.size() % 2 == 1) {
	throw std::domain_error("Hex string with odd character count");
    }

    std::string res;
    for(size_t i=0; i < val.size(); i+=2)
    {
	std::stringstream s;
	int charVal;
	s << val.substr(i, 2) << std::hex;
	s >> charVal;

    	res.append(1, char(charVal));
    }

    return res;
}

Resolver::Resolver(const std::string &trustAnchors):
	m_resolver(ub_ctx_create(), ub_ctx_delete)
{
    try {
    	initializeResolver();
    }
    catch (const ResolverException& e) {
    	FBLOG_FATAL("", e.message());
    }
}

Resolver::~Resolver()
{
}

void Resolver::initializeResolver()
{
    // Unbound initialization
    int ub_retval;

    if (!m_resolver.get()) {
        throw ResolverException("Failed to create ub_ctx resolver");
    }
    
    ub_retval = ub_ctx_add_ta(m_resolver.get(), const_cast<char*>(m_rootTrustAnchor.c_str()));
    if (ub_retval != 0) {
        boost::format fmt("Cannot add trust anchor to resolver: %1%)");
        fmt % std::string(ub_strerror(ub_retval));
        throw ResolverException(fmt.str());
    }
}

TLSAList Resolver::parseResult(const ub_result* result) const
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
    
	    uint8_t *rdf_data = ldns_rdf_data(rdf);
    
	    CertUsage cert_usage = CertUsage(rdf_data[0]);
	    Selector selector = Selector(rdf_data[1]);
	    MatchingType matching_type = MatchingType(rdf_data[2]);
	    std::string association((char *)(rdf_data+3), rdf_size-3);
	    
	    tlsaList.push_back(ResolvedTLSA(cert_usage, selector, matching_type, 
		association, bin2hex(association)));

	    std::string z=hex2bin(bin2hex(association));
	    FBLOG_INFO("-", (z == association) ? "Y" : "N");
	    
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

TLSALookupResult Resolver::fetchTLSA(const std::string& fqdn, int port)
{
    ub_result *resolveResult;
    TLSALookupResult jsResult;
    int retval, rcode;

    jsResult.result = -1;

    if (!canResolve()) {
        jsResult.errorStr = "Resolver initialization failed";
    	return jsResult;
    }
    
    if (port < 1 || port > 0xffff || fqdn.size() < 1) {
        jsResult.errorStr = "Invalid arguments for resolving.";
    	return jsResult;
    }

    boost::format fmt("_%2%._tcp.%1%");
    fmt % fqdn % port;
    std::string rrName = fmt.str();

    retval = ub_resolve(m_resolver.get(), const_cast<char *>(rrName.c_str()), 
        RR_TYPE_TLSA, LDNS_RR_CLASS_IN, &resolveResult);

    if (retval == 0) {
    	jsResult.tlsa = parseResult(resolveResult);
    }
    
    jsResult.result = retval;
    jsResult.rcode = resolveResult->rcode;

    ub_resolve_free(resolveResult);
    
    if (resolveResult->secure) {
    	jsResult.dnssecStatus = TLSAjs::SECURE;
    } else if (resolveResult->bogus) {
    	jsResult.dnssecStatus = TLSAjs::BOGUS;
    	jsResult.errorStr = resolveResult->why_bogus;
    } else {
    	jsResult.dnssecStatus = TLSAjs::INSECURE;
    }
    
    return jsResult;
}

const std::string Resolver::m_rootTrustAnchor(
    ".   IN DS   19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5");
    