# Simple script that will setup some variables to be used for recursive build
# of dependent libraries like openssl, ldns and unbound.

# On Mac, 2.8 is required due to the use of CMAKE_OSX_ARCHITECTURES
# Requirement for 2.8 is specified on Mac branch below.
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
 
PROJECT(C++)

## Variables set by this script:
# OPENSSL_ARGS - args passed to openssl's ./Configure
# CONFIGURE_ARGS - args passed to autotools' ./configure (for ldns and unbound)
# LIB_CFLAGS - CFLAGS for dependent libraries
# TARGET_OS - target OS name build is made for
 
SET(LIB_CFLAGS "${LIB_CFLAGS} -fPIC")

# If build arch is not explicitly set, use current
IF(NOT DEFINED TARGET_ARCH)
    SET(TARGET_ARCH "${CMAKE_SYSTEM_PROCESSOR}")
ENDIF()

# Set flags for dependent libraries, if/else hell on wheels
IF(TARGET_ARCH STREQUAL "x86_64")
    SET(LIB_CFLAGS "${LIB_CFLAGS} -m64")
    SET(BUILD_64BIT 1)
ELSEIF(TARGET_ARCH MATCHES "i.86")
    SET(LIB_CFLAGS "${LIB_CFLAGS} -m32")
    SET(BUILD_64BIT 0)
ELSE()
    MESSAGE(SEND_ERROR "Unsupported architecture - '${TARGET_ARCH}'")
ENDIF()

IF(WIN32)
    SET(TARGET_OS "WINDOWS")
    MESSAGE(SEND_ERROR "Windows build not yet supported")
ELSEIF(UNIX)
    IF(APPLE)
	CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
    	SET(TARGET_OS "MAC")
        IF(BUILD_64BIT)
            SET(OPENSSL_ARGS "darwin64-x86_64-cc ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=x86_64-apple-darwin11")
            SET(CMAKE_OSX_ARCHITECTURES "x86_64")
        ELSE()
            SET(OPENSSL_ARGS "darwin-i386-cc ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=i686-apple-darwin11")
            SET(CMAKE_OSX_ARCHITECTURES "i386")
        ENDIF()
    ELSE() # Linux
    	SET(TARGET_OS "LINUX")
        IF(BUILD_64BIT)
            SET(OPENSSL_ARGS "linux-x86_64 ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=x86_64-pc-linux-gnu")
        ELSE()
            SET(OPENSSL_ARGS "linux-elf ${LIB_CFLAGS}")
            SET(CONFIGURE_ARGS "--target=i686-pc-linux-gnu")
        ENDIF()
    ENDIF()
ENDIF()

# Recursive build using Makefile.main is the target
ADD_CUSTOM_TARGET(RecursiveBuild ALL)

# Calling Makefile.main passing the set variables on command line
ADD_CUSTOM_COMMAND(TARGET RecursiveBuild 
    COMMAND make 
    ARGS -f Makefile.main 
        LIB_CFLAGS=${LIB_CFLAGS}
        OPENSSL_ARGS=${OPENSSL_ARGS} 
        CONFIGURE_ARGS=${CONFIGURE_ARGS} 
	TARGET_OS=${TARGET_OS}
	CMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}

    OUTPUTS DanePatrol.xpi
    )

