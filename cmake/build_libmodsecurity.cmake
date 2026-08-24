# Helper script driven by ExternalProject (see top-level CMakeLists.txt).
# Builds libModSecurity from its Conan-based Windows CMake (build/win32).
#
# Variables (passed via -D on the cmake -P command line):
#   LM_SRC    libModSecurity submodule source root
#   LM_WIN32  libModSecurity/build/win32
#   LM_BUILD  output build directory (import lib + DLL land here)
#   CMAKE_GEN CMake generator to forward (e.g. "Ninja")
#   CMAKE_ARCH architecture passed via -A (e.g. x64)
#
# Note on Conan compiler.version: the GitHub runner ships Visual Studio 2025
# (MSVC 19.5x), which Conan detects as compiler.version=195. ConanCenter has
# no prebuilt binaries for 195, so Conan would build every dependency from
# source -- and it pulls CMake 4.x as a build requirement, which is
# incompatible with old recipes (e.g. yajl 2.1.0). Pinning compiler.version=193
# makes Conan download prebuilt VS2022 binaries instead, which link fine with
# the VS2025 toolchain via the shared dynamic CRT.

set(_log "${LM_BUILD}/build_libmodsecurity.log")
file(REMOVE "${_log}")
file(WRITE "${_log}" "")
set(_rc 0)

function(run cmd)
    math(EXPR _rc "${_rc} + 1")
    set(_tf "${LM_BUILD}/run_${_rc}.log")
    set(_chunk "")
    # NOTE: do not use execute_process(OUTPUT_FILE ... APPEND) -- the APPEND
    # option requires CMake >= 3.17, and the pip "cmake<4" we pin may be older.
    # Capture to a per-call temp file, then fold it into the combined log.
    execute_process(COMMAND ${cmd}
                    OUTPUT_FILE "${_tf}"
                    ERROR_FILE  "${_tf}"
                    RESULT_VARIABLE _r)
    if(EXISTS "${_tf}")
        file(READ "${_tf}" _chunk)
        file(APPEND "${_log}" "${_chunk}")
    endif()
    if(NOT _r EQUAL 0)
        message("---- build_libmodsecurity.cmake: command failed (${_r}) ----")
        message("---- output of: ${cmd} ----")
        message("${_chunk}")
        message(FATAL_ERROR "Command failed (${_r}): ${cmd}")
    endif()
endfunction()

# 0) Make sure a default Conan profile exists (detects the MSVC toolchain).
run("conan;profile;detect;--force")

set(_profile "$ENV{USERPROFILE}/.conan2/profiles/default")
if(EXISTS "${_profile}")
    file(READ "${_profile}" _p)
    string(FIND "${_p}" "cmake/[>=3 <4]" _has_tr)
    if(_has_tr EQUAL -1)
        file(APPEND "${_profile}" "\n[tool_requires]\n!cmake/*: cmake/[>=3 <4]\n")
    endif()
    # Build every dependency with Ninja. The runner ships only VS 2025, so the
    # default "Visual Studio 17 2022" generator implied by compiler.version=193
    # cannot find a VS instance. Ninja uses the MSVC cl.exe already on PATH
    # (set up by ilammy/msvc-dev-cmd) and is version-agnostic.
    string(FIND "${_p}" "generator=Ninja" _has_gen)
    if(_has_gen EQUAL -1)
        file(APPEND "${_profile}" "\n[conf]\ntools.cmake.cmaketoolchain:generator=Ninja\n")
    endif()
endif()

# 1) Resolve dependencies with Conan (generates conan_toolchain.cmake in
#    LM_BUILD and the CMakeDeps files for find_package in the engine CMake).
#    compiler.version=193 => download prebuilt VS2022 binaries (avoid building
#    from source under CMake 4.x). cppstd=17 matches libModSecurity's own
#    CMAKE_CXX_STANDARD and the conancenter poco binaries.
run("conan;install;${LM_WIN32};-s;compiler.version=193;-s;compiler.cppstd=17;-s;compiler.runtime=dynamic;--output-folder=${LM_BUILD};--build=missing;--settings=build_type=Release;--settings=arch=x86_64")

# 2) Configure the engine, forcing output dirs so the import lib / DLL are at
#    predictable paths the top-level CMake imports. `-A` is only valid for the
#    multi-config Visual Studio generators, not for Ninja.
set(_gen_args -G ${CMAKE_GEN})
if(NOT CMAKE_GEN STREQUAL "Ninja")
    list(APPEND _gen_args -A ${CMAKE_ARCH})
endif()

run("cmake;--fresh;-S;${LM_WIN32};-B;${LM_BUILD};${_gen_args};-DCMAKE_TOOLCHAIN_FILE=${LM_BUILD}/conan_toolchain.cmake;-DCMAKE_BUILD_TYPE=Release;-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${LM_BUILD}/bin;-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=${LM_BUILD}/lib;-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${LM_BUILD}/lib;-DWITH_LMDB=OFF;-DWITH_MAXMIND=OFF")

# 3) Build the engine (shared libModSecurity target).
run("cmake;--build;${LM_BUILD};--config;Release")
