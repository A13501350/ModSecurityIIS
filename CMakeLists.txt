cmake_minimum_required(VERSION 3.24)

project(ModSecurityIIS C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# libModSecurity v3 -- built from the submodule source.
#
# The submodule has NO root CMakeLists.txt. Its Windows build lives in
# build/win32/ and is Conan-based (build/win32/conanfile.txt + CMakeLists.txt,
# see vcbuild.bat). We drive that exact build via ExternalProject so a single
# `cmake --build` produces both the engine and this module.
#
# Prerequisites on the Windows build machine:
#   * Visual Studio 2019+ ("Desktop development with C++")
#   * Conan 2.x on PATH (conan install fetches pcre2/libxml2/curl/lua/yajl/
#     poco/dirent/lmdb/maxminddb from the conanfile)
#   * Git on PATH (to init the nested submodules others/libinjection and
#     others/mbedtls that the engine build needs)
#   * IIS + Windows SDK (provides httpserv.h)
# ---------------------------------------------------------------------------
set(LIBMODSECURITY_SRC    ${CMAKE_SOURCE_DIR}/libmodsecurity
    CACHE PATH "libModSecurity submodule source tree")
set(LIBMODSECURITY_WIN32  ${LIBMODSECURITY_SRC}/build/win32)
set(LIBMODSECURITY_BUILD  ${CMAKE_BINARY_DIR}/libmodsecurity_build)

# Initialize the nested submodules the engine build requires.
find_package(Git)
if(Git_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} submodule update --init others/libinjection others/mbedtls
        WORKING_DIRECTORY ${LIBMODSECURITY_SRC}
        RESULT_VARIABLE _lm_submod_r
    )
    if(NOT _lm_submod_r EQUAL 0)
        message(WARNING
            "Could not init nested libModSecurity submodules "
            "(others/libinjection, others/mbedtls). The engine build will fail "
            "unless they are present. Run:\n"
            "  git -C ${LIBMODSECURITY_SRC} submodule update --init others/libinjection others/mbedtls")
    endif()
else()
    message(WARNING "Git not found; cannot auto-init libModSecurity submodules.")
endif()

include(ExternalProject)
ExternalProject_Add(libmodsecurity_ext
    SOURCE_DIR        ${LIBMODSECURITY_SRC}
    CONFIGURE_COMMAND ""   # configure is done inside the build script
    BUILD_COMMAND     ${CMAKE_COMMAND}
                      -D LM_SRC=${LIBMODSECURITY_SRC}
                      -D LM_WIN32=${LIBMODSECURITY_WIN32}
                      -D LM_BUILD=${LIBMODSECURITY_BUILD}
                      -D CMAKE_GEN=${CMAKE_GENERATOR}
                      -D CMAKE_ARCH=x64
                      -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_libmodsecurity.cmake
    INSTALL_COMMAND   ""
    BUILD_IN_SOURCE   0
    # Tell Ninja (and other generators) that this external project produces
    # these files, so the link step for modsecurityiis has a rule for them.
    BUILD_BYPRODUCTS
                      ${LIBMODSECURITY_BUILD}/lib/libModSecurity.lib
                      ${LIBMODSECURITY_BUILD}/bin/libModSecurity.dll
)

# Imported target for the engine DLL/lib produced by the build above.
# Output dirs are forced by the build script, so these paths are predictable.
add_library(libmodsecurity SHARED IMPORTED)
set_target_properties(libmodsecurity PROPERTIES
    IMPORTED_LOCATION ${LIBMODSECURITY_BUILD}/bin/libModSecurity.dll
    IMPORTED_IMPLIB  ${LIBMODSECURITY_BUILD}/lib/libModSecurity.lib
)

# ---------------------------------------------------------------------------
# Event Viewer message resource (compiled from the .mc file with mc.exe).
# Registers the "ModSecurity" event source used by WriteEventViewerLog().
# ---------------------------------------------------------------------------
set(MC_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/src/ModSecurityIISMessage.mc)
set(MC_RC     ${CMAKE_CURRENT_BINARY_DIR}/ModSecurityIISMessage.rc)
set(MC_H      ${CMAKE_CURRENT_BINARY_DIR}/ModSecurityIISMessage.h)

if(MSVC)
    add_custom_command(
        OUTPUT ${MC_RC} ${MC_H}
        COMMAND mc.exe -U -h ${CMAKE_CURRENT_BINARY_DIR} -r ${CMAKE_CURRENT_BINARY_DIR} ${MC_SOURCE}
        DEPENDS ${MC_SOURCE}
        COMMENT "Generating Event Viewer resource from .mc"
        VERIFY_SUPPORTED
    )
endif()

set(MODULE_SOURCES
    src/ModSecurityIIS.cpp
    src/moduleconfig.cpp
    src/connector.cpp
    src/ModSecurityIIS.def
    ${MC_RC}
)

# ---------------------------------------------------------------------------
# The IIS native module.
# `httpserv.h` (IIS Server API) is provided by the Windows SDK + IIS, NOT by
# the engine. The engine's public headers live in libmodsecurity/headers; its
# generated config.h lives in libmodsecurity/src (added for completeness).
# ---------------------------------------------------------------------------
add_library(modsecurityiis SHARED ${MODULE_SOURCES})

target_include_directories(modsecurityiis PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBMODSECURITY_SRC}/headers
    ${LIBMODSECURITY_SRC}/src
)

add_dependencies(modsecurityiis libmodsecurity_ext)

target_link_libraries(modsecurityiis PRIVATE
    libmodsecurity
    ws2_32
    iphlpapi
)

# Copy the engine DLL next to our module so it can be loaded at runtime.
add_custom_command(TARGET modsecurityiis POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${LIBMODSECURITY_BUILD}/bin/libModSecurity.dll
            $<TARGET_FILE_DIR:modsecurityiis>
    DEPENDS libmodsecurity_ext
)

set_target_properties(modsecurityiis PROPERTIES
    OUTPUT_NAME modsecurityiis
    PREFIX ""
    SUFFIX ".dll"
)
