#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "unbound.h"
#include "ldns/ldns.h"
#include "ldns/packet.h"
#include "ldns/wire2host.h"

#define RR_TYPE_TLSA 52

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
		RR_TYPE_TLSA, 
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
                
                ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet, RR_TYPE_TLSA, LDNS_SECTION_ANSWER);
                for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
                        /* extract first rdf, which is the whole TLSA record */
                        ldns_rr *rr = ldns_rr_list_rr(rrs, i);
                        if (ldns_rr_rd_count(rr) < 1) {
                                printf("RR %d does have no RDFs\n", i);
                                return 1;
                        }

                        ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
                        
                        size_t rdf_size = ldns_rdf_size(rdf);
                        if (rdf_size < 4) {
                                printf("TLSA record in RR %d too short\n", i);
                                return 1;
                        }

                        uint8_t cert_usage, selector, matching_type;
                        uint8_t *rdf_data = ldns_rdf_data(rdf);

                        cert_usage = rdf_data[0];
                        selector = rdf_data[1];
                        matching_type = rdf_data[2];
                        
                        printf("RR %d: cert usage %d, selector %d, matching type %d, data ",
                                i, cert_usage, selector, matching_type);
                        int n;
                        for(n=3; n<rdf_size; n++) {
                                printf("%02x", rdf_data[n]);
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
