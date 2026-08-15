#include "daemon/config.h"

#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <limits>
#include <variant>

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

// --- constraints -----------------------------------------------------------
// Integer settings need only a range, which the table states inline. These are
// the ones that do not: each is named after the key it guards and pairs with
// the requirement text quoted back in the error message.

bool valid_freq(double mhz) {
    // 0 means "not set" here; whether that is allowed depends on the radio
    // backend, so load() decides after the whole file is read.
    return mhz == 0.0 || (mhz >= 150.0 && mhz <= 960.0);
}

bool supported_bandwidth(double khz) {
    static constexpr std::array<double, 10> kBandwidths = {
        7.81, 10.42, 15.63, 20.83, 31.25, 41.67, 62.5, 125.0, 250.0, 500.0,
    };
    return std::any_of(kBandwidths.begin(), kBandwidths.end(),
                       [khz](double supported) { return std::fabs(khz - supported) < 0.005; });
}

bool valid_tcxo(double volts) { return volts == 0.0 || (volts >= 1.6 && volts <= 3.3); }

bool valid_duty_cycle(double pct) { return pct > 0.0 && pct < 100.0; }

bool valid_lat(double deg) { return deg >= -90.0 && deg <= 90.0; }

bool valid_lon(double deg) { return deg >= -180.0 && deg <= 180.0; }

// --- the settings table ----------------------------------------------------

// Integer settings land in fields of five different widths. A row holds the
// field's address plus two thunks — read the current value out as the default,
// narrow the checked value back in — so the range check itself happens once, in
// int64, and cannot be skipped for a narrower field.
class IntField {
public:
    template <class T>
    explicit IntField(T& field)
        : field_(&field),
          get_([](const void* p) { return static_cast<int64_t>(*static_cast<const T*>(p)); }),
          set_([](void* p, int64_t v) { *static_cast<T*>(p) = static_cast<T>(v); }) {}

    int64_t get() const { return get_(field_); }
    void set(int64_t v) const { set_(field_, v); }

private:
    void* field_;
    int64_t (*get_)(const void*);
    void (*set_)(void*, int64_t);
};

struct StrTarget {
    std::string* field;
};

struct BoolTarget {
    bool* field;
};

struct IntTarget {
    IntField field;
    int64_t min;
    int64_t max;
};

struct RealTarget {
    double* field;
    bool (*valid)(double);
    // Completes "<key> must be ..." in the error message.
    std::string_view requirement;
};

// One recognised key and where its value goes. The field's current value is the
// default, so defaults stay in config.h beside the fields they belong to.
struct Setting {
    std::string_view key;
    std::variant<StrTarget, BoolTarget, IntTarget, RealTarget> target;
};

Setting Str(std::string_view key, std::string& field) {
    return {key, StrTarget {&field}};
}

Setting Bool(std::string_view key, bool& field) {
    return {key, BoolTarget {&field}};
}

template <class T>
Setting Int(std::string_view key, T& field, int64_t min, int64_t max) {
    return {key, IntTarget {IntField(field), min, max}};
}

Setting Real(std::string_view key, double& field, bool (*valid)(double),
             std::string_view requirement) {
    return {key, RealTarget {&field, valid, requirement}};
}

// The two settings that no single field can hold: a log level arrives as a
// name, and a position arrives as two degrees values that become one
// fixed-point pair. load() converts both once the table has been read.
struct Raw {
    std::string log_level = "info";
    double lat = 0.0;
    double lon = 0.0;
};

// Every key the daemon understands, bound to the fields of `cfg`. Config::keys()
// builds this against a throwaway Config, so a setting cannot exist without
// being listed here for the unknown-key warning and for the shipped
// coreletd.ini, which the tests check against this same list.
std::vector<Setting> settings(Config& cfg, Raw& raw) {
    constexpr int64_t kMaxInt = std::numeric_limits<int>::max();
    constexpr int64_t kMaxU8 = std::numeric_limits<uint8_t>::max();
    constexpr int64_t kMaxU16 = std::numeric_limits<uint16_t>::max();
    // The advert timer is armed in milliseconds in a uint32_t, so a longer
    // interval than this would wrap round to a near-immediate advert.
    constexpr int64_t kMaxTimerDelaySeconds = std::numeric_limits<uint32_t>::max() / 1000;

    return {
        // --- logging and storage ---
        Str("log_level", raw.log_level),
        Str("state_dir", cfg.state_dir),
        Str("identity_path", cfg.identity_path),
        Str("contacts_path", cfg.contacts_path),
        Str("channels_path", cfg.channels_path),

        // --- radio ---
        Bool("mock_radio", cfg.use_mock_radio),
        Str("mock_replay_file", cfg.mock_replay_file),
        Real("lora_freq", cfg.radio.freq_mhz, valid_freq,
             "0 (unset) or between 150 and 960 MHz"),
        Real("lora_bw", cfg.radio.bw_khz, supported_bandwidth,
             "a bandwidth supported by SX1262 (7.81 to 500 kHz)"),
        Int("lora_sf", cfg.radio.sf, 5, 12),
        Int("lora_cr", cfg.radio.cr, 5, 8),
        Int("lora_tx_power", cfg.radio.tx_power_dbm, -9, 22),
        Int("lora_preamble", cfg.radio.preamble, 1, kMaxU16),
        Int("lora_sync_word", cfg.radio.sync_word, 0, kMaxU8),
        Real("lora_tcxo", cfg.radio.tcxo_voltage, valid_tcxo,
             "0 (disabled) or between 1.6 and 3.3 volts"),
        Bool("dio2_as_rf_switch", cfg.radio.dio2_as_rf_switch),
        Bool("rx_boosted_gain", cfg.radio.rx_boosted_gain),
        Int("current_limit", cfg.radio.current_limit_ma, 1, 157),
        Real("duty_cycle", cfg.radio.duty_cycle_pct, valid_duty_cycle,
             "greater than 0 and less than 100 percent"),

        // --- SPI / GPIO ---
        Str("spidev", cfg.spi.spidev),
        Str("lora_gpiochip", cfg.spi.gpiochip),
        Int("lora_irq_pin", cfg.spi.irq_pin, 0, kMaxInt),
        Int("lora_busy_pin", cfg.spi.busy_pin, 0, kMaxInt),
        Int("lora_reset_pin", cfg.spi.reset_pin, 0, kMaxInt),
        // -1 on these three: driven by the SPI controller, or not wired at all.
        Int("lora_nss_pin", cfg.spi.nss_pin, -1, kMaxInt),
        Int("lora_rxen_pin", cfg.spi.rxen_pin, -1, kMaxInt),
        Int("lora_txen_pin", cfg.spi.txen_pin, -1, kMaxInt),
        Int("spi_speed", cfg.spi.spi_speed_hz, 1, 16000000),
        Int("lora_retry_interval", cfg.spi.retry_interval_s, 0, 86400),

        // --- node ---
        Str("advert_name", cfg.node.name),
        Int("advert_interval", cfg.node.advert_interval_s, 0, kMaxTimerDelaySeconds),
        Bool("repeat", cfg.node.repeat),
        Int("max_hops", cfg.node.max_hops, 0, proto::kMaxPathSize),
        Real("lat", raw.lat, valid_lat, "between -90 and 90 degrees"),
        Real("lon", raw.lon, valid_lon, "between -180 and 180 degrees"),

        // --- companion ---
        Str("companion_bind", cfg.companion.bind_addr),
        Int("companion_port", cfg.companion.port, 1, kMaxU16),
    };
}

// Applies one setting, leaving the field at its default when the key is absent.
// Returns false with `error` set on a value that will not parse or that falls
// outside the range the row states.
bool apply(const Ini& ini, const Setting& s, std::string& error) {
    const std::string key(s.key);
    bool ok = true;

    if (const auto* text = std::get_if<StrTarget>(&s.target)) {
        *text->field = ini.get_str(s.key, *text->field);
    } else if (const auto* flag = std::get_if<BoolTarget>(&s.target)) {
        bool value = ini.get_bool(s.key, *flag->field, ok);
        if (!ok) {
            error = key + ": not a boolean";
            return false;
        }
        *flag->field = value;
    } else if (const auto* num = std::get_if<IntTarget>(&s.target)) {
        int64_t value = ini.get_int64(s.key, num->field.get(), ok);
        if (!ok) {
            error = key + ": not an integer";
            return false;
        }
        if (value < num->min || value > num->max) {
            error = key + " must be between " + std::to_string(num->min) + " and " +
                    std::to_string(num->max);
            return false;
        }
        num->field.set(value);
    } else {
        const auto& real = std::get<RealTarget>(s.target);
        double value = ini.get_double(s.key, *real.field, ok);
        if (!ok || !std::isfinite(value)) {
            error = key + ": not a finite number";
            return false;
        }
        if (!real.valid(value)) {
            error = key + " must be " + std::string(real.requirement);
            return false;
        }
        *real.field = value;
    }
    return true;
}

}  // namespace

bool Config::load(const std::string& path, std::string& error) {
    Ini ini;
    if (!ini.load(path, error)) return false;

    // The one default that is discovered rather than declared — it depends on
    // whether we are root — so it cannot sit beside the field in config.h.
    if (state_dir.empty()) state_dir = default_state_dir();

    Raw raw;
    for (const Setting& s : settings(*this, raw))
        if (!apply(ini, s, error)) return false;

    if (!log_parse_level(raw.log_level, log_level)) {
        error = "log_level: unknown level \"" + raw.log_level + "\"";
        return false;
    }

    if (radio.freq_mhz <= 0 && !use_mock_radio) {
        error =
            "lora_freq is required — set the frequency for your region "
            "(e.g. 869.618 for EU868, 910.525 for US915)";
        return false;
    }

    // 0,0 is how the file says "no position", not a point in the Gulf of Guinea.
    node.has_location = raw.lat != 0.0 || raw.lon != 0.0;
    node.lat_e6 = 0;
    node.lon_e6 = 0;
    if (node.has_location) {
        node.lat_e6 = static_cast<int32_t>(std::llround(raw.lat * 1000000.0));
        node.lon_e6 = static_cast<int32_t>(std::llround(raw.lon * 1000000.0));
    }

    for (const auto& key : ini.unread_keys())
        LOG_WARN("config: unknown key \"%s\" ignored", key.c_str());

    return true;
}

std::vector<std::string_view> Config::keys() {
    Config cfg;
    Raw raw;
    std::vector<std::string_view> out;
    for (const Setting& s : settings(cfg, raw)) out.push_back(s.key);
    return out;
}

void Config::finalise() {
    if (identity_path.empty()) identity_path = state_dir + "/identity";
    if (contacts_path.empty()) contacts_path = state_dir + "/contacts";
    if (channels_path.empty()) channels_path = state_dir + "/channels";
}

}  // namespace clt
