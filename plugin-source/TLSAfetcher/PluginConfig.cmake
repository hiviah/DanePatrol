set(PLUGIN_NAME "TLSAfetcher")
set(PLUGIN_PREFIX "TLSA")
set(COMPANY_NAME "CZNICLabs")

# ActiveX constants:
set(FBTYPELIB_NAME TLSAfetcherLib)
set(FBTYPELIB_DESC "TLSAfetcher 1.0 Type Library")
set(IFBControl_DESC "TLSAfetcher Control Interface")
set(FBControl_DESC "TLSAfetcher Control Class")
set(IFBComJavascriptObject_DESC "TLSAfetcher IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "TLSAfetcher ComJavascriptObject Class")
set(IFBComEventSource_DESC "TLSAfetcher IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 7d5774d0-7246-5f59-b97b-2c4256ef957c)
set(IFBControl_GUID 7d865e13-194a-5e6e-bc7c-a73c6f0f9863)
set(FBControl_GUID 98bd8628-d885-59c8-ba2f-35f67ffe8bab)
set(IFBComJavascriptObject_GUID f73d35da-303c-54b9-aabf-ef491f82f656)
set(FBComJavascriptObject_GUID ef6c9587-1bd0-52fd-852e-a83d4f0f474f)
set(IFBComEventSource_GUID 4c89f5b7-2fbe-54d2-86e9-9f2b5d6dc406)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CZNICLabs.TLSAfetcher")
set(MOZILLA_PLUGINID "labs.nic.cz/TLSAfetcher")

# strings
set(FBSTRING_CompanyName "CZ.NIC Labs")
set(FBSTRING_FileDescription "Fetches TLSA records with DNSSEC information")
set(FBSTRING_PLUGIN_VERSION ${XPI_VERSION})
set(FBSTRING_LegalCopyright "Copyright 2012 CZ.NIC Labs")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}.dll")
set(FBSTRING_ProductName "DANE TLSA fetcher")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "DANE TLSA fetcher")
set(FBSTRING_MIMEType "application/x-tlsafetcher")

# Uncomment this next line if you're not planning on your plugin doing
# any drawing:

set (FB_GUI_DISABLED 1)

# Mac plugin settings. If your plugin does not draw, set these all to 0
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_CARBON 0)
set(FBMAC_USE_COCOA 0)
set(FBMAC_USE_COREGRAPHICS 0)
set(FBMAC_USE_COREANIMATION 0)
set(FBMAC_USE_INVALIDATINGCOREANIMATION 0)

# If you want to register per-machine on Windows, uncomment this line
#set (FB_ATLREG_MACHINEWIDE 1)

add_firebreath_library(log4cplus)
add_boost_library(regex)

