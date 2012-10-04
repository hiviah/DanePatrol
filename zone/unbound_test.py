#!/usr/bin/env python
from unbound import ub_ctx, ub_version
from binascii import hexlify

RR_TYPE_TLSA = 52

print "Unbound version:", ub_version()

u = ub_ctx()
u.add_ta_file("keys.tlsa-test")
u.set_fwd("127.0.0.1")
u.set_option("dlv-anchor:", "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh")

for fqdn in ("torproject.org", "labs.nic.cz", "fedoraproject.org", "nohats.ca", "rogue.nohats.ca"):
	s, r = u.resolve("_443._tcp." + fqdn, RR_TYPE_TLSA)
	print "fqdn: %s, status: %s, rcode: %s, secure: %s, bogus: %s, why_bogus: %s" % \
	    (fqdn, s, r.rcode, r.secure, r.bogus, r.why_bogus)
        if r.havedata:
            print [hexlify(rr) for rr in r.data.data]
	
