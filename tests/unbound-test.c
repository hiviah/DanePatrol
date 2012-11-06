#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "unbound.h"
#include "ldns/ldns.h"
#include "ldns/packet.h"
#include "ldns/wire2host.h"

int main(void)
{
	struct ub_ctx* ctx;
	struct ub_result* result;
	int retval, i;
        int exitcode = 0;

	/* create context */
	ctx = ub_ctx_create();
	if(!ctx) {
		printf("error: could not create unbound context\n");
		return 1;
	}
	/* read public keys for DNSSEC verification */
	if( (retval=ub_ctx_add_ta(ctx, ".   IN DS   19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")) != 0) {
		printf("error adding keys: %s\n", ub_strerror(retval));
		return 1;
	}
        if( (retval=ub_ctx_set_option(ctx, "dlv-anchor:", "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh"))) {
		printf("error adding DLV keys: %s\n", ub_strerror(retval));
		return 1;
	}

	/* query for TLSA */
	retval = ub_resolve(ctx, "_443._tcp.www.torproject.org", //"_443._tcp.nohats.ca", 
		LDNS_RR_TYPE_TLSA, 
		1 /* CLASS IN (internet) */, &result);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return 1;
	}

	/* show first result */
	if(result->havedata) {
                ldns_pkt *packet;
                ldns_status parse_status = ldns_wire2pkt(&packet, (uint8_t*)(result->answer_packet), result->answer_len);
                
                if (parse_status != LDNS_STATUS_OK) {
                        printf("Failed to parse response packet\n");
                        return 1;
                }
                
                ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);
                for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
                        /* extract first rdf, which is the whole TLSA record */
                        ldns_rr *rr = ldns_rr_list_rr(rrs, i);
                        
                        // Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
                        // instead of 1 RDF in ldns 1.6.13.
                        if (ldns_rr_rd_count(rr) < 4) {
                                printf("RR %d hasn't enough fields\n", i);
                                return 1;
                        }

                        ldns_rdf *rdf_cert_usage    = ldns_rr_rdf(rr, 0),
                                 *rdf_selector      = ldns_rr_rdf(rr, 1),
                                 *rdf_matching_type = ldns_rr_rdf(rr, 2),
                                 *rdf_association   = ldns_rr_rdf(rr, 3);
                        
                        if (ldns_rdf_size(rdf_cert_usage)       != 1 ||
                            ldns_rdf_size(rdf_selector)         != 1 ||
                            ldns_rdf_size(rdf_matching_type)    != 1 ||
                            ldns_rdf_size(rdf_association)      < 0
                            ) {
                                printf("Improperly formatted TLSA RR %d\n", i);
                                return 1;
                        }

                        uint8_t cert_usage, selector, matching_type;
                        uint8_t *association;
                        size_t association_size;

                        cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
                        selector = ldns_rdf_data(rdf_selector)[0];
                        matching_type = ldns_rdf_data(rdf_matching_type)[0];
                        association = ldns_rdf_data(rdf_association);
                        association_size = ldns_rdf_size(rdf_association);
                        
                        printf("RR %d: cert usage %d, selector %d, matching type %d, data ",
                                i, cert_usage, selector, matching_type);
                        int n;
                        for(n=0; n<association_size; n++) {
                                printf("%02x", association[n]);
                        }
                        printf("\n");

                        ldns_rr_free(rr);
                }
                
                ldns_pkt_free(packet);
                ldns_rr_list_free(rrs);
        } else {
                printf("We haven't received any data\n");
                return 1;
        }

	/* show security status */
	if(result->secure) {
		printf("Result is secure\n");
	} else if(result->bogus) {
		printf("Result is bogus: %s\n", result->why_bogus);
                exitcode = 1;
	} else 	{
                printf("Result is insecure\n");
                exitcode = 1;
        }

	ub_resolve_free(result);
	ub_ctx_delete(ctx);
	return exitcode;
}
