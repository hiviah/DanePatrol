#!/usr/bin/env python
from unbound import ub_ctx, ub_version
from binascii import hexlify

RR_TYPE_TLSA = 52

print "Unbound version:", ub_version()

u = ub_ctx()
u.add_ta_file("keys.tlsa-test")
u.set_fwd("127.0.0.1")

for fqdn in ("_443._tcp.tlsa-test", "_443._tcp.labs.nic.cz"):
	s, r = u.resolve(fqdn, RR_TYPE_TLSA)
	print "fqdn: %s, status: %s, rcode: %s, secure: %s, bogus: %s, why_bogus: %s" % \
	    (fqdn, s, r.rcode, r.secure, r.bogus, r.why_bogus)
        if r.havedata:
            print [hexlify(rr) for rr in r.data.data]
	
