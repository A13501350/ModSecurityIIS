# Helper script driven by ExternalProject (see top-level CMakeLists.txt).
# Builds libModSecurity from its Conan-based Windows CMake (build/win32).
#
# Variables (passed via -D on the cmake -P command line):
#   LM_SRC    libModSecurity submodule source root
#   LM_WIN32  libModSecurity/build/win32
#   LM_BUILD  output build directory (import lib + DLL land here)
#   CMAKE_GEN CMake generator to forward (e.g. "Visual Studio 17 2022")
#   CMAKE_ARCH architecture passed via -A (e.g. x64)

function(run cmd)
    execute_process(COMMAND ${cmd} RESULT_VARIABLE _r)
    if(NOT _r EQUAL 0)
        message(FATAL_ERROR "Command failed (${_r}): ${cmd}")
    endif()
endfunction()

# 0) Make sure a default Conan profile exists (detects the MSVC toolchain).
run("conan;profile;detect;--force")

# 1) Resolve dependencies with Conan (generates conan_toolchain.cmake in
#    LM_BUILD and the CMakeDeps files for find_package in the engine CMake).
run("conan;install;${LM_WIN32};-s;compiler.cppstd=17;--output-folder=${LM_BUILD};--build=missing;--settings=build_type=Release;--settings=arch=x86_64")

# 2) Configure the engine, forcing output dirs so the import lib / DLL are at
#    predictable paths the top-level CMake imports.
run("cmake;--fresh;-S;${LM_WIN32};-B;${LM_BUILD};-G;${CMAKE_GEN};-A;${CMAKE_ARCH};-DCMAKE_TOOLCHAIN_FILE=${LM_BUILD}/conan_toolchain.cmake;-DCMAKE_BUILD_TYPE=Release;-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${LM_BUILD}/bin;-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=${LM_BUILD}/lib;-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${LM_BUILD}/lib;-DWITH_LMDB=OFF;-DWITH_MAXMIND=OFF")

# 3) Build the engine (shared libModSecurity target).
run("cmake;--build;${LM_BUILD};--config;Release")
