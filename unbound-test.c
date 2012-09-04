#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unbound.h>

int main(void)
{
	struct ub_ctx* ctx;
	struct ub_result* result;
	int retval;

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

	/* query for webserver */
	retval = ub_resolve(ctx, "www.nlnetlabs.nl", 
		1 /* TYPE A (IPv4 address) */, 
		1 /* CLASS IN (internet) */, &result);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return 1;
	}

	/* show first result */
	if(result->havedata)
		printf("The address is %s\n", 
			inet_ntoa(*(struct in_addr*)result->data[0]));
	/* show security status */
	if(result->secure)
		printf("Result is secure\n");
	else if(result->bogus)
		printf("Result is bogus: %s\n", result->why_bogus);
	else 	printf("Result is insecure\n");

	ub_resolve_free(result);
	ub_ctx_delete(ctx);
	return 0;
}
