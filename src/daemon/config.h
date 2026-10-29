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

    // Required, absolute, and must already exist. Everything the node is lives
    // in it under fixed names, so the directory is the whole of a backup.
    std::string state_dir;
    std::string identity_path() const { return state_dir + "/identity"; }
    std::string contacts_path() const { return state_dir + "/contacts"; }
    std::string channels_path() const { return state_dir + "/channels"; }
    std::string messages_path() const { return state_dir + "/messages"; }
    std::string settings_path() const { return state_dir + "/settings"; }

    radio::RadioParams radio;
    SpiConfig spi;

    mesh::Node::Config node;
    companion::Server::Options companion;

    // Loads the config file and applies it over the defaults above. Returns
    // false with `error` set on a malformed file or an out-of-range value. The
    // keys an app may change are not read from it: they are the settings
    // file's, and a line for one is warned about and ignored.
    bool load(const std::string& path, std::string& error);

    // The checks no one key can make: the advert name has to fit beside the
    // position, for one. Run on what the settings file makes of the defaults,
    // and again on every change the app asks for.
    bool validate(std::string& error) const;

    // Every key the config file takes, in file order. Derived from the same
    // table load() reads, so a setting cannot be added without turning up
    // here; the tests use it to hold the shipped coreletd.ini to the same key
    // set.
    static std::vector<std::string_view> keys();

    // The keys a companion app may change, and so the only ones get() and set()
    // take and the settings file may hold. None of them is a key().
    static bool app_key(std::string_view key);
    static std::vector<std::string_view> app_keys();

    // An app key's value, as the settings file writes it: one spelling per
    // value, so two can be compared as text.
    std::string get(std::string_view key) const;
    // Parses `value` into an app key with the checks its line in the settings
    // file gets. Returns false with `error` set otherwise.
    bool set(std::string_view key, std::string_view value, std::string& error);

    // Hands the subsystems the paths they own, once state_dir is final.
    void finalise();
};

// Default config file location, overridable with --config.
inline constexpr const char* kDefaultConfigPath = "/etc/coreletd/coreletd.ini";

}  // namespace clt
