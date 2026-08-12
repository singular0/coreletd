#include "daemon/config.h"

#include <pwd.h>
#include <unistd.h>

#include <filesystem>

#include "util/ini.h"

namespace umc {

namespace {

std::string default_state_dir() {
    // Running as a system service: use the systemd StateDirectory. Running as a
    // user: fall back to the XDG data dir so no root is needed for a test run.
    if (::geteuid() == 0) return "/var/lib/umeshcore";

    if (const char* xdg = ::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::string(xdg) + "/umeshcore";
    if (const char* home = ::getenv("HOME"); home && *home)
        return std::string(home) + "/.local/share/umeshcore";
    return "./umeshcore-state";
}

}  // namespace

bool Config::load(const std::string& path, std::string& error) {
    Ini ini;
    if (!ini.load(path, error)) return false;

    // --- logging ---
    std::string level = ini.get_str("log_level", "info");
    if (!log_parse_level(level, log_level)) {
        error = "log_level: unknown level \"" + level + "\"";
        return false;
    }

    // --- storage ---
    state_dir = ini.get_str("state_dir", default_state_dir());

    // --- radio ---
    bool ok = true;
    radio.freq_mhz = ini.get_double("lora_freq", 0.0, ok);
    if (!ok) {
        error = "lora_freq: not a number";
        return false;
    }
    use_mock_radio = ini.get_bool("mock_radio", false);
    mock_replay_file = ini.get_str("mock_replay_file");

    if (radio.freq_mhz <= 0 && !use_mock_radio) {
        error =
            "lora_freq is required — set the frequency for your region "
            "(e.g. 869.618 for EU868, 910.525 for US915)";
        return false;
    }

    radio.bw_khz = ini.get_double("lora_bw", radio.bw_khz);
    radio.sf = static_cast<uint8_t>(ini.get_int("lora_sf", radio.sf));
    radio.cr = static_cast<uint8_t>(ini.get_int("lora_cr", radio.cr));
    radio.tx_power_dbm = static_cast<int>(ini.get_int("lora_tx_power", radio.tx_power_dbm));
    radio.preamble = static_cast<uint16_t>(ini.get_int("lora_preamble", radio.preamble));
    radio.sync_word = static_cast<uint8_t>(ini.get_int("lora_sync_word", radio.sync_word));
    radio.tcxo_voltage = ini.get_double("lora_tcxo", radio.tcxo_voltage);
    radio.dio2_as_rf_switch = ini.get_bool("dio2_as_rf_switch", radio.dio2_as_rf_switch);
    radio.rx_boosted_gain = ini.get_bool("rx_boosted_gain", radio.rx_boosted_gain);
    radio.current_limit_ma = static_cast<int>(ini.get_int("current_limit", radio.current_limit_ma));
    radio.duty_cycle_pct = ini.get_double("duty_cycle", radio.duty_cycle_pct);

    if (radio.sf < 5 || radio.sf > 12) {
        error = "lora_sf must be between 5 and 12";
        return false;
    }
    if (radio.cr < 5 || radio.cr > 8) {
        error = "lora_cr must be between 5 and 8 (the 4/N denominator)";
        return false;
    }
    if (radio.tx_power_dbm < -9 || radio.tx_power_dbm > 22) {
        error = "lora_tx_power must be between -9 and 22 dBm";
        return false;
    }

    // --- SPI / GPIO ---
    spi.spidev = ini.get_str("spidev", spi.spidev);
    spi.gpiochip = ini.get_str("lora_gpiochip", spi.gpiochip);
    spi.irq_pin = static_cast<int>(ini.get_int("lora_irq_pin", spi.irq_pin));
    spi.busy_pin = static_cast<int>(ini.get_int("lora_busy_pin", spi.busy_pin));
    spi.reset_pin = static_cast<int>(ini.get_int("lora_reset_pin", spi.reset_pin));
    spi.nss_pin = static_cast<int>(ini.get_int("lora_nss_pin", spi.nss_pin));
    spi.rxen_pin = static_cast<int>(ini.get_int("lora_rxen_pin", spi.rxen_pin));
    spi.txen_pin = static_cast<int>(ini.get_int("lora_txen_pin", spi.txen_pin));
    spi.power_enable_pin =
        static_cast<int>(ini.get_int("lora_power_enable_pin", spi.power_enable_pin));
    spi.spi_speed_hz = static_cast<uint32_t>(ini.get_int("spi_speed", spi.spi_speed_hz));

    // --- node ---
    node.name = ini.get_str("advert_name", node.name);
    node.advert_interval_s =
        static_cast<uint32_t>(ini.get_int("advert_interval", node.advert_interval_s));
    node.repeat = ini.get_bool("repeat", node.repeat);
    node.max_hops = static_cast<uint8_t>(ini.get_int("max_hops", node.max_hops));

    double lat = ini.get_double("lat", 0.0);
    double lon = ini.get_double("lon", 0.0);
    if (lat != 0.0 || lon != 0.0) {
        node.has_location = true;
        node.lat_e6 = static_cast<int32_t>(lat * 1000000.0);
        node.lon_e6 = static_cast<int32_t>(lon * 1000000.0);
    }

    // --- companion ---
    companion.bind_addr = ini.get_str("companion_bind", companion.bind_addr);
    companion.port = static_cast<uint16_t>(ini.get_int("companion_port", companion.port));

    // Explicit path overrides.
    identity_path = ini.get_str("identity_path");
    contacts_path = ini.get_str("contacts_path");
    channels_path = ini.get_str("channels_path");

    for (const auto& key : ini.unread_keys())
        LOG_WARN("config: unknown key \"%s\" ignored", key.c_str());

    return true;
}

void Config::finalise() {
    if (identity_path.empty()) identity_path = state_dir + "/identity";
    if (contacts_path.empty()) contacts_path = state_dir + "/contacts";
    if (channels_path.empty()) channels_path = state_dir + "/channels";
}

}  // namespace umc
