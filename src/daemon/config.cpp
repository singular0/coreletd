#include "daemon/config.h"

#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <filesystem>
#include <limits>

#include "util/ini.h"

namespace clt {

namespace {

std::string default_state_dir() {
    // Running as a system service: use the systemd StateDirectory. Running as a
    // user: fall back to the XDG data dir so no root is needed for a test run.
    if (::geteuid() == 0) return "/var/lib/coreletd";

    if (const char* xdg = ::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::string(xdg) + "/coreletd";
    if (const char* home = ::getenv("HOME"); home && *home)
        return std::string(home) + "/.local/share/coreletd";
    return "./coreletd-state";
}

bool read_int(const Ini& ini, std::string_view key, int64_t def, int64_t min, int64_t max,
              int64_t& value, std::string& error) {
    bool ok = true;
    value = ini.get_int64(key, def, ok);
    if (!ok) {
        error = std::string(key) + ": not an integer";
        return false;
    }
    if (value < min || value > max) {
        error = std::string(key) + " must be between " + std::to_string(min) + " and " +
                std::to_string(max);
        return false;
    }
    return true;
}

bool read_double(const Ini& ini, std::string_view key, double def, double& value,
                 std::string& error) {
    bool ok = true;
    value = ini.get_double(key, def, ok);
    if (!ok || !std::isfinite(value)) {
        error = std::string(key) + ": not a finite number";
        return false;
    }
    return true;
}

bool read_bool(const Ini& ini, std::string_view key, bool def, bool& value,
               std::string& error) {
    bool ok = true;
    value = ini.get_bool(key, def, ok);
    if (!ok) {
        error = std::string(key) + ": not a boolean";
        return false;
    }
    return true;
}

bool supported_bandwidth(double khz) {
    static constexpr std::array<double, 10> kBandwidths = {
        7.81, 10.42, 15.63, 20.83, 31.25, 41.67, 62.5, 125.0, 250.0, 500.0,
    };
    return std::any_of(kBandwidths.begin(), kBandwidths.end(),
                       [khz](double supported) { return std::fabs(khz - supported) < 0.005; });
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
    bool boolean = false;
    if (!read_bool(ini, "mock_radio", use_mock_radio, boolean, error)) return false;
    use_mock_radio = boolean;
    mock_replay_file = ini.get_str("mock_replay_file");

    double real = 0.0;
    if (!read_double(ini, "lora_freq", radio.freq_mhz, real, error)) return false;
    if (real != 0.0 && (real < 150.0 || real > 960.0)) {
        error = "lora_freq must be between 150 and 960 MHz";
        return false;
    }
    radio.freq_mhz = real;
    if (radio.freq_mhz <= 0 && !use_mock_radio) {
        error =
            "lora_freq is required — set the frequency for your region "
            "(e.g. 869.618 for EU868, 910.525 for US915)";
        return false;
    }

    if (!read_double(ini, "lora_bw", radio.bw_khz, real, error)) return false;
    if (!supported_bandwidth(real)) {
        error = "lora_bw must be a bandwidth supported by SX1262 (7.81 to 500 kHz)";
        return false;
    }
    radio.bw_khz = real;

    int64_t integer = 0;
    if (!read_int(ini, "lora_sf", radio.sf, 5, 12, integer, error)) return false;
    radio.sf = static_cast<uint8_t>(integer);
    if (!read_int(ini, "lora_cr", radio.cr, 5, 8, integer, error)) return false;
    radio.cr = static_cast<uint8_t>(integer);
    if (!read_int(ini, "lora_tx_power", radio.tx_power_dbm, -9, 22, integer, error))
        return false;
    radio.tx_power_dbm = static_cast<int>(integer);
    if (!read_int(ini, "lora_preamble", radio.preamble, 1,
                  std::numeric_limits<uint16_t>::max(), integer, error))
        return false;
    radio.preamble = static_cast<uint16_t>(integer);
    if (!read_int(ini, "lora_sync_word", radio.sync_word, 0,
                  std::numeric_limits<uint8_t>::max(), integer, error))
        return false;
    radio.sync_word = static_cast<uint8_t>(integer);

    if (!read_double(ini, "lora_tcxo", radio.tcxo_voltage, real, error)) return false;
    if (real != 0.0 && (real < 1.6 || real > 3.3)) {
        error = "lora_tcxo must be 0 (disabled) or between 1.6 and 3.3 volts";
        return false;
    }
    radio.tcxo_voltage = real;
    if (!read_bool(ini, "dio2_as_rf_switch", radio.dio2_as_rf_switch, boolean, error))
        return false;
    radio.dio2_as_rf_switch = boolean;
    if (!read_bool(ini, "rx_boosted_gain", radio.rx_boosted_gain, boolean, error))
        return false;
    radio.rx_boosted_gain = boolean;
    if (!read_int(ini, "current_limit", radio.current_limit_ma, 1, 157, integer, error))
        return false;
    radio.current_limit_ma = static_cast<int>(integer);
    if (!read_double(ini, "duty_cycle", radio.duty_cycle_pct, real, error)) return false;
    if (real <= 0.0 || real >= 100.0) {
        error = "duty_cycle must be greater than 0 and less than 100 percent";
        return false;
    }
    radio.duty_cycle_pct = real;

    // --- SPI / GPIO ---
    spi.spidev = ini.get_str("spidev", spi.spidev);
    spi.gpiochip = ini.get_str("lora_gpiochip", spi.gpiochip);
    constexpr int64_t kMaxInt = std::numeric_limits<int>::max();
    if (!read_int(ini, "lora_irq_pin", spi.irq_pin, 0, kMaxInt, integer, error)) return false;
    spi.irq_pin = static_cast<int>(integer);
    if (!read_int(ini, "lora_busy_pin", spi.busy_pin, 0, kMaxInt, integer, error)) return false;
    spi.busy_pin = static_cast<int>(integer);
    if (!read_int(ini, "lora_reset_pin", spi.reset_pin, 0, kMaxInt, integer, error)) return false;
    spi.reset_pin = static_cast<int>(integer);
    if (!read_int(ini, "lora_nss_pin", spi.nss_pin, -1, kMaxInt, integer, error)) return false;
    spi.nss_pin = static_cast<int>(integer);
    if (!read_int(ini, "lora_rxen_pin", spi.rxen_pin, -1, kMaxInt, integer, error)) return false;
    spi.rxen_pin = static_cast<int>(integer);
    if (!read_int(ini, "lora_txen_pin", spi.txen_pin, -1, kMaxInt, integer, error)) return false;
    spi.txen_pin = static_cast<int>(integer);
    if (!read_int(ini, "spi_speed", spi.spi_speed_hz, 1, 16000000, integer, error))
        return false;
    spi.spi_speed_hz = static_cast<uint32_t>(integer);
    if (!read_int(ini, "lora_retry_interval", spi.retry_interval_s, 0, 86400, integer,
                  error))
        return false;
    spi.retry_interval_s = static_cast<uint32_t>(integer);

    // --- node ---
    node.name = ini.get_str("advert_name", node.name);
    constexpr int64_t kMaxTimerDelaySeconds = std::numeric_limits<uint32_t>::max() / 1000;
    if (!read_int(ini, "advert_interval", node.advert_interval_s, 0, kMaxTimerDelaySeconds,
                  integer, error))
        return false;
    node.advert_interval_s = static_cast<uint32_t>(integer);
    if (!read_bool(ini, "repeat", node.repeat, boolean, error)) return false;
    node.repeat = boolean;
    if (!read_int(ini, "max_hops", node.max_hops, 0, proto::kMaxPathSize, integer, error))
        return false;
    node.max_hops = static_cast<uint8_t>(integer);

    double lat = 0.0;
    double lon = 0.0;
    if (!read_double(ini, "lat", 0.0, lat, error)) return false;
    if (!read_double(ini, "lon", 0.0, lon, error)) return false;
    if (lat < -90.0 || lat > 90.0) {
        error = "lat must be between -90 and 90 degrees";
        return false;
    }
    if (lon < -180.0 || lon > 180.0) {
        error = "lon must be between -180 and 180 degrees";
        return false;
    }
    node.has_location = false;
    node.lat_e6 = 0;
    node.lon_e6 = 0;
    if (lat != 0.0 || lon != 0.0) {
        node.has_location = true;
        node.lat_e6 = static_cast<int32_t>(std::llround(lat * 1000000.0));
        node.lon_e6 = static_cast<int32_t>(std::llround(lon * 1000000.0));
    }

    // --- companion ---
    companion.bind_addr = ini.get_str("companion_bind", companion.bind_addr);
    if (!read_int(ini, "companion_port", companion.port, 1,
                  std::numeric_limits<uint16_t>::max(), integer, error))
        return false;
    companion.port = static_cast<uint16_t>(integer);

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

}  // namespace clt
