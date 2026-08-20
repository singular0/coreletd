#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "companion/server.h"
#include "mesh/node.h"
#include "radio/radio.h"
#include "util/log.h"

namespace clt {

struct SpiConfig {
    std::string spidev = "/dev/spidev1.0";
    // uConsole AIO v2: SPI1 with CE0 on GPIO18, handled by the kernel driver.
    std::string gpiochip = "gpiochip0";
    int irq_pin = 26;    // DIO1
    int busy_pin = 24;
    int reset_pin = 25;
    int nss_pin = -1;    // -1 == chip select driven by the SPI controller
    int rxen_pin = -1;
    int txen_pin = -1;
    uint32_t spi_speed_hz = 2000000;
    // The AIO v2 gates power to each subsystem and the daemon does not touch
    // those switches, so the SX1262 may be absent at startup or vanish while
    // running. Seconds between attempts to (re)connect to it, and between the
    // liveness checks that notice it going away. 0 disables both, making an
    // unresponsive radio a startup failure again.
    uint32_t retry_interval_s = 10;
};

struct Config {
    LogLevel log_level = LogLevel::Info;
    bool log_syslog_style = false;

    std::string state_dir;
    std::string identity_path;
    std::string contacts_path;
    std::string channels_path;
    std::string messages_path;

    radio::RadioParams radio;
    SpiConfig spi;

    mesh::Node::Config node;
    companion::Server::Options companion;

    // Loads the file and applies it over the defaults above. Returns false with
    // `error` set on a malformed file or an out-of-range value.
    bool load(const std::string& path, std::string& error);

    // Every key load() understands, in file order. Derived from the same table
    // load() reads, so a setting cannot be added without turning up here; the
    // tests use it to hold the shipped coreletd.ini to the same key set.
    static std::vector<std::string_view> keys();

    // Fills in state paths from state_dir when they were not set explicitly.
    void finalise();
};

// Default config file location, overridable with --config.
inline constexpr const char* kDefaultConfigPath = "/etc/coreletd/coreletd.ini";

}  // namespace clt
