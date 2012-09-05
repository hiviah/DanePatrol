/**********************************************************\

  Auto-generated TLSAfetcherAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"

#include "TLSAfetcherAPI.h"

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAfetcherAPI::TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr host)
///
/// @brief  Constructor for your JSAPI object.  You should register your methods, properties, and events
///         that should be accessible to Javascript from here.
///
/// @see FB::JSAPIAuto::registerMethod
/// @see FB::JSAPIAuto::registerProperty
/// @see FB::JSAPIAuto::registerEvent
///////////////////////////////////////////////////////////////////////////////
TLSAfetcherAPI::TLSAfetcherAPI(const TLSAfetcherPtr& plugin, const FB::BrowserHostPtr& host) : m_plugin(plugin), m_host(host)
{
    registerMethod("echo",      make_method(this, &TLSAfetcherAPI::echo));
    registerMethod("testEvent", make_method(this, &TLSAfetcherAPI::testEvent));

    // Read-write property
    registerProperty("testString",
                     make_property(this,
                        &TLSAfetcherAPI::get_testString,
                        &TLSAfetcherAPI::set_testString));

    // Read-only property
    registerProperty("version",
                     make_property(this,
                        &TLSAfetcherAPI::get_version));
}

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAfetcherAPI::~TLSAfetcherAPI()
///
/// @brief  Destructor.  Remember that this object will not be released until
///         the browser is done with it; this will almost definitely be after
///         the plugin is released.
///////////////////////////////////////////////////////////////////////////////
TLSAfetcherAPI::~TLSAfetcherAPI()
{
}

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAfetcherPtr TLSAfetcherAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
TLSAfetcherPtr TLSAfetcherAPI::getPlugin()
{
    TLSAfetcherPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}



// Read/Write property testString
std::string TLSAfetcherAPI::get_testString()
{
    return m_testString;
}
void TLSAfetcherAPI::set_testString(const std::string& val)
{
    m_testString = val;
}

// Read-only property version
std::string TLSAfetcherAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}

// Method echo
FB::variant TLSAfetcherAPI::echo(const FB::variant& msg)
{
    static int n(0);
    fire_echo(msg, n++);
    return msg;
}

void TLSAfetcherAPI::testEvent(const FB::variant& var)
{
    fire_fired(var, true, 1);
}

