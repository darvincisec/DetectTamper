# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(LIBZ_PATH ${CMAKE_HOME_DIRECTORY}/../../../../libzip)
set(MBEDTLS_PATH ${CMAKE_HOME_DIRECTORY}/../../../../mbedtls)
set(MARKER_PATH ${CMAKE_HOME_DIRECTORY}/marker)
set(CORE_PATH ${CMAKE_HOME_DIRECTORY}/core)
set(GO_PATH ${CMAKE_HOME_DIRECTORY}/../../../../injecthash)

SET(CMAKE_C_VISIBILITY_PRESET hidden)

file(GLOB_RECURSE MBEDTLS_SRC ${MBEDTLS_PATH}/crypto/library/*.c)

add_library(start OBJECT ${MARKER_PATH}/text_start.c)
add_library(end OBJECT ${MARKER_PATH}/text_end.c)

add_library(
        core
        # Sets the library as a shared library.
        OBJECT
        # Provides a relative path to your source file(s).
        ${CORE_PATH}/native-lib.c
        ${MBEDTLS_SRC}
)

target_include_directories(core PRIVATE ${MBEDTLS_PATH}/include ${MBEDTLS_PATH}/crypto/include ${LIBZ_PATH}/${ANDROID_ABI}/include/)

add_library(native-lib SHARED dummy.c)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

find_library(zlib z)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.
target_link_libraries(native-lib $<TARGET_OBJECTS:start> $<TARGET_OBJECTS:core> ${LIBZ_PATH}/${ANDROID_ABI}/lib/libzip.a $<TARGET_OBJECTS:end> ${zlib} ${log-lib} )

if(NOT GO_EXECUTABLE)
    set(GO_EXECUTABLE "go")
endif()

if(NOT GO_EXECUTABLE)
    message(FATAL_ERROR "Could not find Go")
endif()

add_custom_command( TARGET native-lib
        POST_BUILD
        COMMAND ${GO_EXECUTABLE} run ${GO_PATH}/injecthash.go ${CMAKE_HOME_DIRECTORY}/../../../build/intermediates/cmake/${CMAKE_BUILD_TYPE}/obj/${ANDROID_ABI}/libnative-lib.so
        COMMENT "Injected Hashes"
)

add_custom_command( TARGET native-lib
        POST_BUILD
        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -R .comment -g -S -d --strip-unneeded ${CMAKE_HOME_DIRECTORY}/../../../build/intermediates/cmake/${CMAKE_BUILD_TYPE}/obj/${ANDROID_ABI}/libnative-lib.so
        COMMENT "Stripped native library"
)
