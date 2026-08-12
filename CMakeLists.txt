cmake_minimum_required(VERSION 3.16)
project(umeshcore
    VERSION 0.1.0
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
    set(_umeshcore_sx1262_default ON)
else()
    set(_umeshcore_sx1262_default OFF)
endif()

option(UMESHCORE_RADIO_SX1262 "Build the Linux SX1262 radio backend (spidev + libgpiod)"
       ${_umeshcore_sx1262_default})
option(UMESHCORE_BUILD_TESTS "Build the test suite" ON)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(CRYPTO REQUIRED IMPORTED_TARGET libcrypto)

if(UMESHCORE_RADIO_SX1262)
    pkg_check_modules(GPIOD REQUIRED IMPORTED_TARGET libgpiod)
    if(GPIOD_VERSION VERSION_LESS "2.0")
        message(FATAL_ERROR
            "libgpiod ${GPIOD_VERSION} found, but >= 2.0 is required. "
            "On Raspberry Pi OS trixie: apt install libgpiod-dev")
    endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Core library (everything except main(), so tests can link it)
# ---------------------------------------------------------------------------

add_library(umeshcore_core STATIC
    src/util/log.cpp
    src/util/hex.cpp
    src/util/ini.cpp
    src/util/clock.cpp
    src/util/persist.cpp
    src/crypto/crypto.cpp
    src/crypto/identity.cpp
    src/proto/packet.cpp
    src/proto/payloads.cpp
    src/radio/mock_radio.cpp
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

target_include_directories(umeshcore_core PUBLIC src)
target_link_libraries(umeshcore_core
    PUBLIC PkgConfig::SODIUM PkgConfig::CRYPTO Threads::Threads)
target_compile_options(umeshcore_core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)

target_compile_definitions(umeshcore_core PUBLIC
    UMESHCORE_VERSION="${PROJECT_VERSION}")

if(UMESHCORE_RADIO_SX1262)
    target_sources(umeshcore_core PRIVATE
        src/radio/spidev.cpp
        src/radio/gpio.cpp
        src/radio/sx1262.cpp
    )
    target_link_libraries(umeshcore_core PUBLIC PkgConfig::GPIOD)
    target_compile_definitions(umeshcore_core PUBLIC UMESHCORE_HAVE_SX1262=1)
endif()

# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

add_executable(umeshcored src/main.cpp)
target_link_libraries(umeshcored PRIVATE umeshcore_core)

include(GNUInstallDirs)
install(TARGETS umeshcored RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES etc/umeshcored.ini DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/umeshcore)

# systemd and udev read these from under the prefix itself, not from a
# multiarch libdir, so CMAKE_INSTALL_LIBDIR would be wrong here.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    install(FILES etc/umeshcored.service DESTINATION lib/systemd/system)
    install(FILES etc/99-umeshcore.rules DESTINATION lib/udev/rules.d)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(UMESHCORE_BUILD_TESTS)
    enable_testing()
    foreach(t crypto packet ini companion mesh)
        add_executable(test_${t} tests/test_${t}.cpp)
        target_link_libraries(test_${t} PRIVATE umeshcore_core)
        # Tests include their helpers as "tests/...", so the project root must
        # be on the include path as well as src/.
        target_include_directories(test_${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        add_test(NAME ${t} COMMAND test_${t})
    endforeach()
endif()

message(STATUS "umeshcore ${PROJECT_VERSION}")
message(STATUS "  SX1262 radio backend : ${UMESHCORE_RADIO_SX1262}")
message(STATUS "  tests                : ${UMESHCORE_BUILD_TESTS}")
