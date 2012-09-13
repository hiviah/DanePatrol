/*! 
 * @file Factory.cpp
 * @brief Autogenerated factory with logging enabled manually
 *
 */
 

#include "FactoryBase.h"
#include "TLSAfetcher.h"
#include <boost/make_shared.hpp>

class PluginFactory : public FB::FactoryBase
{
public:
    ///////////////////////////////////////////////////////////////////////////////
    /// @fn FB::PluginCorePtr createPlugin(const std::string& mimetype)
    ///
    /// @brief  Creates a plugin object matching the provided mimetype
    ///         If mimetype is empty, returns the default plugin
    ///////////////////////////////////////////////////////////////////////////////
    FB::PluginCorePtr createPlugin(const std::string& mimetype)
    {
        return boost::make_shared<TLSAfetcher>();
    }
    
    ///////////////////////////////////////////////////////////////////////////////
    /// @see FB::FactoryBase::globalPluginInitialize
    ///////////////////////////////////////////////////////////////////////////////
    void globalPluginInitialize()
    {
        TLSAfetcher::StaticInitialize();
    }
    
    ///////////////////////////////////////////////////////////////////////////////
    /// @see FB::FactoryBase::globalPluginDeinitialize
    ///////////////////////////////////////////////////////////////////////////////
    void globalPluginDeinitialize()
    {
        TLSAfetcher::StaticDeinitialize();
    }
};

///////////////////////////////////////////////////////////////////////////////
/// @fn getFactoryInstance()
///
/// @brief  Returns the factory instance for this plugin module
///////////////////////////////////////////////////////////////////////////////
FB::FactoryBasePtr getFactoryInstance()
{
    static boost::shared_ptr<PluginFactory> factory = boost::make_shared<PluginFactory>();
    return factory;
}

void getLoggingMethods( FB::Log::LogMethodList& outMethods )
{
    // The next line will enable logging to the console (think: printf).
    outMethods.push_back(std::make_pair(FB::Log::LogMethod_Console, std::string()));
 
    // The next line will enable logging to a logfile.
//    outMethods.push_back(std::make_pair(FB::Log::LogMethod_File, "/foo/bar/baz.log"));
 
    // Obviously, if you use both lines, you will get output on both sinks.
}

FB::Log::LogLevel getLogLevel(){
    return FB::Log::LogLevel_Debug;
}
