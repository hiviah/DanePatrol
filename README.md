DANE Patrol
===========

DANE Patrol is fork of Certificate Patrol which brings in implementation of RFC
6698 to validate SSL/TLS certificates. 

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

NPAPI/JS plugin test
-----------------------

FireBreath generates `FireBreath/build/projects/TLSAfetcher/gen/FBControl.htm`
page which can be used to test NPAPI-JS with Firebug before using it in addon
code. E.g. in Firebug's console:

    plugin().checkDANE("nlnetlabs.nl", 443, ["DERbody1", "DERbody2"], 1)

