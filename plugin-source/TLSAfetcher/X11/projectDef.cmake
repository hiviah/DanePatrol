#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# DANE TLSA fetcher project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in X11/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    X11/[^.]*.cpp
    X11/[^.]*.h
    X11/[^.]*.cmake
    )

SOURCE_GROUP(X11 FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJECT_NAME} SOURCES)

# set header file directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/ldns/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/unbound/include)

# set static library paths
add_library(unbound STATIC IMPORTED)
set_property(TARGET unbound PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/unbound/lib/libunbound.a)

add_library(ldns STATIC IMPORTED)
set_property(TARGET ldns PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/ldns/lib/libldns.a)

add_library(ssl STATIC IMPORTED)
set_property(TARGET ssl PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/lib/libssl.a)

add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/lib/libcrypto.a)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    unbound
    ldns
    ssl
    crypto
    )
