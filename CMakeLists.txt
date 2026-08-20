cmake_minimum_required(VERSION 3.16)
project(coreletd
    DESCRIPTION "MeshCore daemon for ClockworkPi uConsole + AIO v2"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_coreletd_sx1262_default ON)
else()
    set(_coreletd_sx1262_default OFF)
endif()

option(CORELETD_RADIO_SX1262 "Build the Linux SX1262 radio backend (spidev + libgpiod)"
       ${_coreletd_sx1262_default})
option(CORELETD_BUILD_TESTS "Build the test suite" ON)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(CRYPTO REQUIRED IMPORTED_TARGET libcrypto)

if(CORELETD_RADIO_SX1262)
    pkg_check_modules(GPIOD REQUIRED IMPORTED_TARGET libgpiod)
    if(GPIOD_VERSION VERSION_LESS "2.0")
        message(FATAL_ERROR
            "libgpiod ${GPIOD_VERSION} found, but >= 2.0 is required. "
            "On Raspberry Pi OS trixie: apt install libgpiod-dev")
    endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

# There is no version number in this file: `git describe` against the release
# tags is the one source, so a build cannot claim a version nobody tagged.
# Resolve once while configuring so the generated header exists, then again
# before every build so a new tag, a new commit or a dirty tracked file shows
# up without a manual reconfigure. Packaging passes CORELETD_VERSION_MANIFEST
# to freeze every output to a single Git observation while it builds from a
# staged copy that has no .git of its own.
set(CORELETD_VERSION_MANIFEST "" CACHE FILEPATH
    "Frozen version manifest supplied by a packaging build")
set(CORELETD_GENERATED_MANIFEST ${CMAKE_CURRENT_BINARY_DIR}/coreletd-version.cmake)
set(CORELETD_VERSION_HEADER ${CMAKE_CURRENT_BINARY_DIR}/version.h)
set(CORELETD_MANPAGE ${CMAKE_CURRENT_BINARY_DIR}/coreletd.8)
set(version_command
    ${CMAKE_COMMAND}
    -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
    -DOUTPUT_MANIFEST=${CORELETD_GENERATED_MANIFEST}
    -DOUTPUT_HEADER=${CORELETD_VERSION_HEADER}
    -DOUTPUT_MANPAGE=${CORELETD_MANPAGE}
    -DMANPAGE_TEMPLATE=${CMAKE_CURRENT_SOURCE_DIR}/etc/coreletd.8.in)
if(CORELETD_VERSION_MANIFEST)
    list(APPEND version_command -DINPUT_MANIFEST=${CORELETD_VERSION_MANIFEST})
endif()
list(APPEND version_command -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake)
execute_process(COMMAND ${version_command} RESULT_VARIABLE version_status)
if(NOT version_status EQUAL 0)
    message(FATAL_ERROR "cannot resolve the coreletd version")
endif()
include(${CORELETD_GENERATED_MANIFEST})

# ---------------------------------------------------------------------------
# Core library (everything except main(), so tests can link it)
# ---------------------------------------------------------------------------

add_library(coreletd_core STATIC
    src/util/log.cpp
    src/util/hex.cpp
    src/util/ini.cpp
    src/util/clock.cpp
    src/util/persist.cpp
    src/crypto/crypto.cpp
    src/crypto/identity.cpp
    src/proto/packet.cpp
    src/proto/payloads.cpp
    src/radio/radio.cpp
    src/mesh/contacts.cpp
    src/mesh/channels.cpp
    src/mesh/dispatcher.cpp
    src/mesh/inbox.cpp
    src/mesh/sender.cpp
    src/mesh/state_writer.cpp
    src/mesh/node.cpp
    src/companion/frames.cpp
    src/companion/server.cpp
    src/companion/session.cpp
    src/daemon/config.cpp
    src/daemon/eventloop.cpp
    src/daemon/host_metrics.cpp
    src/daemon/app.cpp
)

# The binary directory is on the include path for the generated version.h.
target_include_directories(coreletd_core PUBLIC src ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(coreletd_core
    PUBLIC PkgConfig::SODIUM PkgConfig::CRYPTO Threads::Threads)
target_compile_options(coreletd_core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)

# Re-resolved before every build, not just at configure time, so an
# already-configured tree still reports the commit it was actually built from.
add_custom_target(coreletd-version
    BYPRODUCTS ${CORELETD_GENERATED_MANIFEST} ${CORELETD_VERSION_HEADER}
               ${CORELETD_MANPAGE}
    COMMAND ${version_command}
    COMMENT "Resolving the version from git"
    VERBATIM)
add_dependencies(coreletd_core coreletd-version)

if(CORELETD_RADIO_SX1262)
    target_sources(coreletd_core PRIVATE
        src/radio/spidev.cpp
        src/radio/gpio.cpp
        src/radio/sx1262.cpp
    )
    target_link_libraries(coreletd_core PUBLIC PkgConfig::GPIOD)
    target_compile_definitions(coreletd_core PUBLIC CORELETD_HAVE_SX1262=1)
endif()

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

add_executable(coreletd src/main.cpp)
target_link_libraries(coreletd PRIVATE coreletd_core)

include(GNUInstallDirs)
install(TARGETS coreletd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES etc/coreletd.ini DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/coreletd)
# The man page is generated rather than shipped, so that its .TH line carries
# the same version as the binary beside it; debhelper picks it up from the
# install tree instead of a debian/coreletd.manpages listing.
install(FILES ${CORELETD_MANPAGE} DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)

# systemd and udev read these from under the prefix itself, not from a
# multiarch libdir, so CMAKE_INSTALL_LIBDIR would be wrong here.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(FILES etc/coreletd.service DESTINATION lib/systemd/system)
    install(FILES etc/99-coreletd.rules DESTINATION lib/udev/rules.d)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(CORELETD_BUILD_TESTS)
    enable_testing()
    foreach(t bytes crypto packet ini eventloop companion mesh radio app)
        add_executable(test_${t} tests/test_${t}.cpp)
        target_link_libraries(test_${t} PRIVATE coreletd_core)
        # Tests include their helpers as "tests/...", so the project root must
        # be on the include path as well as src/.
        target_include_directories(test_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        # Some tests read shipped files (etc/coreletd.ini) rather than only
        # headers, and are run from the build tree.
        target_compile_definitions(test_${t} PRIVATE
            CORELETD_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()

    # The resolver decides what every package and binary calls itself, and it
    # runs before any C++ exists, so it is tested on its own: the test builds
    # throwaway repositories and checks what each one resolves to.
    add_test(NAME version
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/version_test.cmake)
endif()

message(STATUS "coreletd ${CORELETD_VERSION}")
message(STATUS "  SX1262 radio backend : ${CORELETD_RADIO_SX1262}")
message(STATUS "  tests                : ${CORELETD_BUILD_TESTS}")
