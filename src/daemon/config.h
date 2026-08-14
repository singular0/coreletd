#pragma once

#include <string>

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

    radio::RadioParams radio;
    SpiConfig spi;
    bool use_mock_radio = false;
    std::string mock_replay_file;

    mesh::Node::Config node;
    companion::Server::Options companion;

    // Loads the file and applies it over the defaults above. Returns false with
    // `error` set on a malformed file or an out-of-range value.
    bool load(const std::string& path, std::string& error);

    // Fills in state paths from state_dir when they were not set explicitly.
    void finalise();
};

// Default config file location, overridable with --config.
inline constexpr const char* kDefaultConfigPath = "/etc/coreletd/coreletd.ini";

}  // namespace clt
