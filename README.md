DANE Patrol
===========

DANE Patrol is fork of Certificate Patrol which brings in implementation of RFC
6698 to validate SSL/TLS certificates. 

Features
--------

- Supports multiple certificates for a site (useful for CDN services a la
  google). If a cert is known in the addon's DB, no popup/warning will show, but
  TLSA check can still be done if set in preferences.
- Check for DANE can be turned off entirely and DANE Patrol can be used as
  Certificate Patrol (for people not liking the binary NPAPI plugin)
- Successful DANE check will override warning for a new cert (like CertPatrol
  used to show if too many things changed), only notification is shown.
- By default DANE is checked only for new certs or for host that are recorded to
  have had TLSA before (seemed like most sensible default since TLSA is not yet
  spread; can be changed in preferences)
- Overriding "this certificate is not trusted" page is not yet implemented
- The details page for new or changed certificate show which TLSA record matched
  (cert usage, matching type and selector).

Limitations
-----------

The "Reject" button will only reject to store the certificate, it can't abort
connection. Firefox API has no way of doing that. Similarly a bad TLSA (a MitM
attack) will display a warning, but can't abort the connection. This isn't such
a problem for a toplevel site, but could matter for instance if bank's main site
is bank.com, but login is posted to secure.bank.com through POST via a form on
the page.

These above notes (sans TLSA stuff) apply to Certificate Patrol as well (haven't
seen that described anywhere, found out when digging in code).

Known bugs and quirks
---------------------

- Overriding "certificate is not trusted" page is not yet implemented.
- Each certificate is checked at most once in a Firefox's session (until you
  close it). There's a cache to limit the DB checks and TLSA queries. So once a
  certificate passes TLSA test, it will stay valid even if you change TLSA
  before restarting Firefox. This could affect TLSA records with very short
  TTLs.
- Due to the above, you'll get only one warning about failed TLSA check for a
  cert.
- Usage type 2 or 3 will match if a site's cert is transitively trusted by PKIX
  check of Firefox from its trust anchors. This is a policy in this
  implementation - reasoning is that if a cert is trusted, the result of the
  TLSA check is the same as if we used the associated cert as trust anchor (I
  could be wrong, but seems to make sense so far).
- Full RELRO, PIE, stack protector and similar settings should be made global
  for all sub-libraries used in the project.

Building
--------

Currently the build is Linux only (maybe could work on \*BSD). Windows version
will need modifying the Makefile to use MSVC, Mac version needs to use Xcode to
compile the NPAPI plugin.

### Build requirements

- gcc (possibly clang &gt;= 3.0, 2.8 will fail)
- autotools (autoconf, automake, make)
- cmake &gt;= 2.6
- git (Makefile pulls submodules)
- python, python-yaml

To build the Firefox addon with NPAPI plugin, use just `make`. Resulting
`DanePatrol.xpi` should appear at toplevel directory. For running
tests, `make test-run`.

At the moment, all debugging information are kept in the NPAPI plugin binary, so
it's a bit large. Later in production version it'll be split with strip, objcopy
and friends.

NPAPI/JS plugin test
-----------------------

The following test requires that you comment out the check whether plugin is
instantiated from Firefox toplevel chrome (it's in
plugin-source/TLSAfetcher/TLSAfetcherAPI.cpp, the if testing for `chrome.xul`).

FireBreath generates `FireBreath/build/projects/TLSAfetcher/gen/FBControl.htm`
page which can be used to test NPAPI-JS with Firebug before using it in addon
code. E.g. in Firebug's console:

    plugin().checkDANE("nlnetlabs.nl", 443, ["DERbody1", "DERbody2"], 1)

