#!/usr/bin/env python

# Extract version from given install.rdf as arg0.
# The <em:version> element contents is used and printed out.
# Minimal error checking is performed, an error raises exception.

import sys
import xml.dom.minidom

doc = xml.dom.minidom.parse(sys.argv[1])
# minidom doesn't support XML namespaces or XPath, but we don't want to add
# another dependency on something like lxml or 4Suite
versionElem = doc.getElementsByTagName('em:version')[0]
# We expect that there's only single version element with only single #text
# child node.
version = versionElem.firstChild.nodeValue

print version
