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
- The details page for new or changed certificate show which TLSA record matched
  (cert usage, matching type and selector).
- Can override "this certificate is untrusted" page if TLSA with certificate
  usage 2 or 3 matches and user allows the override in preferences

Limitations
-----------

The "Reject" button will only reject to store the certificate, it can't abort
connection immediately after SSL/TLS handshake. Similarly a bad TLSA (a MitM
attack) will display a warning, but can't abort the connection before first
request is made. This isn't such a problem for a toplevel site, but could
matter for instance if bank's main site is bank.com, but login is posted to
secure.bank.com through POST via a form on the page.

These above notes (sans TLSA stuff) apply to Certificate Patrol as well (haven't
seen that described anywhere, found out when digging in code).

Known bugs and quirks
---------------------

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
- check for TLSA is synchronous, i.e. may appear to "freeze" Firefox for a
  while, especially if there's many domains used for a page's resources (no way
  around this without changing Firefox)
- IDN domains are not yet supported

Building
--------

Currently the build works on Linux and Mac OS X (Windows requires some extra
hacking).

### Build requirements

- gcc (possibly clang &gt;= 3.0, 2.8 will fail)
- autotools (autoconf, automake, make)
- cmake &gt;= 2.6 (cmake &gt;= 2.8 for Mac)
- git (Makefile pulls submodules)
- python, python-yaml
- platform dependent stuff:
  - Linux: GTK+ 2 development libraries (usually named `gtk2-devel` or
    `libgtk2.0-dev`)
  - Mac: Xcode (FireBreath says it needs it, but seems not necessary when we
    use `prepmake.sh` instead of `prepmac.sh`)

### Build parameters of CMake

Toplevel CMake takes one parameter `TARGET_ARCH` which can be either `i686` or
`x86_64`. If not specified, cmake script will try to guess the arch based on
current machine environment. This works fairly well for Linux, but for Mac
there is a well-known bug of CMake reporting 32-bit arch even if machine is
`x86_64`.

Thus in general the build is done by invoking CMake, then make (note the dot
at the end of cmake invocation):

    cmake [-DTARGET_ARCH=(x86_64|i686)] .
    make

Do not mix builds for two architectures in one cloned repo tree (build system
is not that far yet).

### Build on Linux

Just call cmake and make without any extra parameters:

    cmake .
    make

### Build on Mac

It's recommended to set explicitly the target architecture on Mac since CMake
may guess it wrong (see above), e.g.:

    cmake -DTARGET_ARCH=x86_64 .
    make

### Other make targets (tests, clean)

Some usual targets like `clean` and `distclean` were moved to `Makefile.main`
when CMake was introduced into the mix. Thus invocation:

    make -f Makefile.main clean         #clean intermediate compile files
    make -f Makefile.main distclean     #clean everything, including built libs
    make -f Makefile.main test          #build tests
    make -f Makefile.main test-run      #run tests (build if necessary)

