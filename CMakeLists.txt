cmake_minimum_required(VERSION 3.20)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

project(scef
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "Self-contained Encrypted Container Format"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Compiler warnings ---
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# --- Use LLD linker when available ---
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(MSVC)
        add_link_options(-fuse-ld=lld-link)
    else()
        add_link_options(-fuse-ld=lld)
    endif()
endif()

# --- Dependencies ---
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(BOTAN IMPORTED_TARGET botan-3)
endif()

if(NOT BOTAN_FOUND)
    find_package(Botan 3 CONFIG QUIET)
endif()

find_package(nlohmann_json CONFIG REQUIRED)

# vcpkg may place Botan headers in include/botan/ instead of include/botan-3/botan/,
# causing the Botan CMake config to fail to set include directories.
# Detect and fix this by adding the vcpkg include path directly.
if(NOT TARGET Botan::Botan AND NOT TARGET PkgConfig::BOTAN AND DEFINED VCPKG_INSTALLED_DIR)
    set(_vcpkg_botan_include "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
    set(_vcpkg_botan_lib "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib/botan-3.lib")
    if(EXISTS "${_vcpkg_botan_include}/botan" AND EXISTS "${_vcpkg_botan_lib}")
        add_library(Botan::Botan SHARED IMPORTED)
        set_target_properties(Botan::Botan PROPERTIES
            IMPORTED_IMPLIB "${_vcpkg_botan_lib}"
            INTERFACE_INCLUDE_DIRECTORIES "${_vcpkg_botan_include}"
        )
        message(STATUS "Botan 3 found via vcpkg fallback: ${_vcpkg_botan_include}")
    endif()
endif()

# --- Sources ---
set(SCEF_SOURCES
    src/main.cpp
    src/Header.cpp
    src/CryptoManager.cpp
    src/FileManager.cpp
    src/FileTable.cpp
)

# --- Main executable ---
add_executable(scef ${SCEF_SOURCES})

target_include_directories(scef PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(TARGET PkgConfig::BOTAN)
    target_link_libraries(scef PRIVATE PkgConfig::BOTAN)
elseif(TARGET Botan::Botan)
    target_link_libraries(scef PRIVATE Botan::Botan)
else()
    message(WARNING "Botan 3 not found. Build will fail at link time.")
endif()

target_link_libraries(scef PRIVATE nlohmann_json::nlohmann_json)

# --- Tests (optional) ---
option(SCEF_BUILD_TESTS "Build unit tests" ON)
if(SCEF_BUILD_TESTS)
    enable_testing()
    # Tests will be added here as they are created
endif()
