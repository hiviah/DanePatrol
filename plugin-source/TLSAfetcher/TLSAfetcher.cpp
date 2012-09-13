/*! 
 * @file TLSAfetcher.cpp
 * @brief NPAPI plugin interface base implementation
 *
 */
 

#include "logging.h"

#include "TLSAfetcherAPI.h"

#include "TLSAfetcher.h"


/*! Shared global resolver structure. It should be thread-safe. */

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAfetcher::StaticInitialize()
///
/// @brief  Called from PluginFactory::globalPluginInitialize()
///
/// @see FB::FactoryBase::globalPluginInitialize
///////////////////////////////////////////////////////////////////////////////
void TLSAfetcher::StaticInitialize()
{
    FB::Log::initLogging();
}

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAfetcher::StaticInitialize()
///
/// @brief  Called from PluginFactory::globalPluginDeinitialize()
///
/// @see FB::FactoryBase::globalPluginDeinitialize
///////////////////////////////////////////////////////////////////////////////
void TLSAfetcher::StaticDeinitialize()
{
}

///////////////////////////////////////////////////////////////////////////////
/// @brief  TLSAfetcher constructor.  Note that your API is not available
///         at this point, nor the window.  For best results wait to use
///         the JSAPI object until the onPluginReady method is called
///////////////////////////////////////////////////////////////////////////////
TLSAfetcher::TLSAfetcher()
{
}

///////////////////////////////////////////////////////////////////////////////
/// @brief  TLSAfetcher destructor.
///////////////////////////////////////////////////////////////////////////////
TLSAfetcher::~TLSAfetcher()
{
    // This is optional, but if you reset m_api (the shared_ptr to your JSAPI
    // root object) and tell the host to free the retained JSAPI objects then
    // unless you are holding another shared_ptr reference to your JSAPI object
    // they will be released here.
    releaseRootJSAPI();
    m_host->freeRetainedObjects();
}

void TLSAfetcher::onPluginReady()
{
    // When this is called, the BrowserHost is attached, the JSAPI object is
    // created, and we are ready to interact with the page and such.  The
    // PluginWindow may or may not have already fire the AttachedEvent at
    // this point.
}

void TLSAfetcher::shutdown()
{
    // This will be called when it is time for the plugin to shut down;
    // any threads or anything else that may hold a shared_ptr to this
    // object should be released here so that this object can be safely
    // destroyed. This is the last point that shared_from_this and weak_ptr
    // references to this object will be valid
}

///////////////////////////////////////////////////////////////////////////////
/// @brief  Creates an instance of the JSAPI object that provides your main
///         Javascript interface.
///
/// Note that m_host is your BrowserHost and shared_ptr returns a
/// FB::PluginCorePtr, which can be used to provide a
/// boost::weak_ptr<TLSAfetcher> for your JSAPI class.
///
/// Be very careful where you hold a shared_ptr to your plugin class from,
/// as it could prevent your plugin class from getting destroyed properly.
///////////////////////////////////////////////////////////////////////////////
FB::JSAPIPtr TLSAfetcher::createJSAPI()
{
    // m_host is the BrowserHost
    return boost::make_shared<TLSAfetcherAPI>(FB::ptr_cast<TLSAfetcher>(shared_from_this()), m_host);
}

bool TLSAfetcher::onMouseDown(FB::MouseDownEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse down at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}

bool TLSAfetcher::onMouseUp(FB::MouseUpEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse up at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}

bool TLSAfetcher::onMouseMove(FB::MouseMoveEvent *evt, FB::PluginWindow *)
{
    //printf("Mouse move at: %d, %d\n", evt->m_x, evt->m_y);
    return false;
}
bool TLSAfetcher::onWindowAttached(FB::AttachedEvent *evt, FB::PluginWindow *)
{
    // The window is attached; act appropriately
    return false;
}

bool TLSAfetcher::onWindowDetached(FB::DetachedEvent *evt, FB::PluginWindow *)
{
    // The window is about to be detached; act appropriately
    return false;
}

