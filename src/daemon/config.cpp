#include "daemon/config.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <limits>
#include <variant>

#include "proto/payloads.h"
#include "util/ini.h"

namespace clt {

namespace {

// --- constraints -----------------------------------------------------------
// Integer settings need only a range, which the table states inline. These are
// the ones that do not: each is named after the key it guards and pairs with
// the requirement text quoted back in the error message.

bool valid_freq(double mhz) {
    // 0 is "not set": the daemon starts with the radio idle and transmits
    // nothing until an app names a frequency. The range is what the SX1262 can
    // tune, checked on the centre frequency alone, as MeshCore checks it.
    return mhz == 0.0 || (mhz >= 150.0 && mhz <= 960.0);
}

bool supported_bandwidth(double khz) {
    return std::any_of(radio::kBandwidthsKhz.begin(), radio::kBandwidthsKhz.end(),
                       [khz](double supported) { return std::fabs(khz - supported) < 0.005; });
}

bool valid_tcxo(double volts) { return volts == 0.0 || (volts >= 1.6 && volts <= 3.3); }

// 100 is no limit, which is what an app asks for with an airtime factor of 0.
bool valid_duty_cycle(double pct) { return pct > 0.0 && pct <= 100.0; }

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

// A position: written in decimal degrees, held in the millionths the advert
// carries.
struct DegreesTarget {
    int32_t* field;
    bool (*valid)(double);
    std::string_view requirement;
};

// One recognised key and where its value goes. The field's current value is the
// default, so defaults stay in config.h beside the fields they belong to — and
// for the keys an app may change, the defaults are all there is until it does.
struct Setting {
    std::string_view key;
    std::variant<StrTarget, BoolTarget, IntTarget, RealTarget, DegreesTarget> target;
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

Setting Degrees(std::string_view key, int32_t& field, bool (*valid)(double),
                std::string_view requirement) {
    return {key, DegreesTarget {&field, valid, requirement}};
}

// The two settings that arrive as names of enum values. load() converts both
// once the table has been read.
struct Raw {
    std::string log_level = "info";
    std::string companion_interface = "unix";
};

// What MeshCore's companion keeps in its own preferences and lets an app
// change: the node's name and position, the radio preset, the TX power, the
// airtime budget and repeat. These live in the settings file and nowhere else,
// so each has one owner; everything else is the operator's, in the config file.
constexpr std::string_view kAppKeys[] = {
    "radio.lora_freq",  "radio.lora_bw", "radio.lora_sf", "radio.lora_cr", "radio.lora_tx_power",
    "radio.duty_cycle", "node.advert_name", "node.lat", "node.lon", "node.repeat",
};

// Every key the daemon understands, in either file, bound to the fields of
// `cfg`. Config::keys() builds this against a throwaway Config, so a setting
// cannot exist without being listed here for the unknown-key warning and for
// the shipped coreletd.ini, which the tests check against this same list.
std::vector<Setting> settings(Config& cfg, Raw& raw) {
    constexpr int64_t kMaxInt = std::numeric_limits<int>::max();
    constexpr int64_t kMaxU16 = std::numeric_limits<uint16_t>::max();
    // The advert timer is armed in milliseconds in a uint32_t, so a longer
    // interval than this would wrap round to a near-immediate advert.
    constexpr int64_t kMaxTimerDelaySeconds = std::numeric_limits<uint32_t>::max() / 1000;

    return {
        // --- radio ---
        Real("radio.lora_freq", cfg.radio.freq_mhz, valid_freq,
             "0 (unset) or between 150 and 960 MHz"),
        Real("radio.lora_bw", cfg.radio.bw_khz, supported_bandwidth,
             "a bandwidth supported by SX1262 (7.81 to 500 kHz)"),
        Int("radio.lora_sf", cfg.radio.sf, 5, 12),
        Int("radio.lora_cr", cfg.radio.cr, 5, 8),
        Int("radio.lora_tx_power", cfg.radio.tx_power_dbm, radio::kMinTxPowerDbm,
            radio::kMaxTxPowerDbm),
        Real("radio.duty_cycle", cfg.radio.duty_cycle_pct, valid_duty_cycle,
             "greater than 0 and less than 100 percent"),

        // --- hardware ---
        Str("hardware.spidev", cfg.spi.spidev),
        Str("hardware.lora_gpiochip", cfg.spi.gpiochip),
        Int("hardware.lora_irq_pin", cfg.spi.irq_pin, 0, kMaxInt),
        Int("hardware.lora_busy_pin", cfg.spi.busy_pin, 0, kMaxInt),
        Int("hardware.lora_reset_pin", cfg.spi.reset_pin, 0, kMaxInt),
        // -1 on these three: driven by the SPI controller, or not wired at all.
        Int("hardware.lora_nss_pin", cfg.spi.nss_pin, -1, kMaxInt),
        Int("hardware.lora_rxen_pin", cfg.spi.rxen_pin, -1, kMaxInt),
        Int("hardware.lora_txen_pin", cfg.spi.txen_pin, -1, kMaxInt),
        Int("hardware.lora_retry_interval", cfg.spi.retry_interval_s, 0, 86400),
        Bool("hardware.dio2_as_rf_switch", cfg.radio.dio2_as_rf_switch),
        Real("hardware.lora_tcxo", cfg.radio.tcxo_voltage, valid_tcxo,
             "0 (disabled) or between 1.6 and 3.3 volts"),
        Bool("hardware.rx_boosted_gain", cfg.radio.rx_boosted_gain),
        Int("hardware.current_limit", cfg.radio.current_limit_ma, 1, 157),
        Int("hardware.spi_speed", cfg.spi.spi_speed_hz, 1, 16000000),

        // --- node ---
        Str("node.advert_name", cfg.node.name),
        Int("node.advert_interval", cfg.node.advert_interval_s, 0, kMaxTimerDelaySeconds),
        Degrees("node.lat", cfg.node.lat_e6, valid_lat, "between -90 and 90 degrees"),
        Degrees("node.lon", cfg.node.lon_e6, valid_lon, "between -180 and 180 degrees"),
        Bool("node.repeat", cfg.node.repeat),
        Int("node.max_hops", cfg.node.max_hops, 0, proto::kMaxPathSize),

        // --- companion ---
        Str("companion.companion_interface", raw.companion_interface),
        Str("companion.companion_socket", cfg.companion.socket_path),
        Str("companion.companion_bind", cfg.companion.bind_addr),
        Int("companion.companion_port", cfg.companion.port, 1, kMaxU16),

        // --- storage ---
        Str("storage.state_dir", cfg.state_dir),

        // --- logging ---
        Str("logging.log_level", raw.log_level),
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
    } else if (const auto* real = std::get_if<RealTarget>(&s.target)) {
        double value = ini.get_double(s.key, *real->field, ok);
        if (!ok || !std::isfinite(value)) {
            error = key + ": not a finite number";
            return false;
        }
        if (!real->valid(value)) {
            error = key + " must be " + std::string(real->requirement);
            return false;
        }
        *real->field = value;
    } else {
        const auto& deg = std::get<DegreesTarget>(s.target);
        double value = ini.get_double(s.key, *deg.field / 1e6, ok);
        if (!ok || !std::isfinite(value)) {
            error = key + ": not a finite number";
            return false;
        }
        if (!deg.valid(value)) {
            error = key + " must be " + std::string(deg.requirement);
            return false;
        }
        *deg.field = static_cast<int32_t>(std::llround(value * 1e6));
    }
    return true;
}

// The fewest decimals that read back as exactly `v`, so 869.618 is written as
// that rather than as the binary fraction nearest to it, and 100 as 100 rather
// than 1e+02. Every value the table holds is in range of a fixed point.
std::string format_real(double v) {
    char buf[64];
    for (int decimals = 0; decimals <= 17; decimals++) {
        snprintf(buf, sizeof(buf), "%.*f", decimals, v);
        if (std::strtod(buf, nullptr) == v) return buf;
    }
    snprintf(buf, sizeof(buf), "%.17g", v);
    return buf;
}

std::string format(const Setting& s) {
    if (const auto* text = std::get_if<StrTarget>(&s.target)) return *text->field;
    if (const auto* flag = std::get_if<BoolTarget>(&s.target)) return *flag->field ? "1" : "0";
    if (const auto* num = std::get_if<IntTarget>(&s.target))
        return std::to_string(num->field.get());
    if (const auto* real = std::get_if<RealTarget>(&s.target)) return format_real(*real->field);
    return format_real(*std::get<DegreesTarget>(s.target).field / 1e6);
}

}  // namespace

bool Config::load(const std::string& path, std::string& error) {
    Ini ini;
    if (!ini.load(path, error)) return false;

    Raw raw;
    for (const Setting& s : settings(*this, raw))
        if (!app_key(s.key) && !apply(ini, s, error)) return false;

    if (!log_parse_level(raw.log_level, log_level)) {
        error = "logging.log_level: unknown level \"" + raw.log_level + "\"";
        return false;
    }

    if (raw.companion_interface == "unix") {
        companion.transport = clt::companion::Server::Transport::Unix;
    } else if (raw.companion_interface == "tcp") {
        companion.transport = clt::companion::Server::Transport::Tcp;
    } else {
        error = "companion.companion_interface must be \"unix\" or \"tcp\"";
        return false;
    }

    // No default, because every guess was a different node: root and everyone
    // else used to land in different directories, and a relative path changes
    // with whoever's working directory the daemon starts in.
    if (state_dir.empty()) {
        error = "storage.state_dir is required — the directory holding this node's identity, "
                "contacts, channels and messages (/var/lib/coreletd for the packaged service)";
        return false;
    }
    if (state_dir.front() != '/') {
        error = "storage.state_dir must be an absolute path, not \"" + state_dir + "\"";
        return false;
    }
    while (state_dir.size() > 1 && state_dir.back() == '/') state_dir.pop_back();

    for (const auto& key : ini.unread_keys()) {
        if (app_key(key))
            LOG_WARN("config: %s ignored — it is set from a companion app, or in %s",
                     key.c_str(), settings_path().c_str());
        else
            LOG_WARN("config: unknown key \"%s\" ignored", key.c_str());
    }

    return true;
}

bool Config::validate(std::string& error) const {
    // The advert has to fit in the 32 bytes MeshCore verifies, and the budget
    // depends on whether a position is being advertised, so this cannot be a
    // range on the setting itself. Refuse rather than truncate: the failure
    // mode otherwise is silence at both ends — peers log a forged signature and
    // drop us, and nothing here says why nobody ever answers.
    // Not reachable from a file — an empty value falls back to the default —
    // but the invariant is worth holding anyway: BaseChatMesh::onAdvertRecv
    // discards any advert without a name, so a nameless node is invisible to
    // chat clients even when its signature verifies.
    if (node.name.empty()) {
        error = "node.advert_name must not be empty — MeshCore clients ignore adverts with no name";
        return false;
    }
    // Only an app can send one, and no client shows it as anything but
    // garbage; a line break would also end the value in the settings file.
    if (std::any_of(node.name.begin(), node.name.end(),
                    [](unsigned char c) { return c < 0x20 || c == 0x7f; })) {
        error = "node.advert_name must not contain control characters";
        return false;
    }
    const size_t overhead = 1 + (node.has_location() ? 8 : 0);  // flags, lat+lon
    const size_t budget = proto::kMaxAdvertAppDataSize - overhead;
    if (node.name.size() > budget) {
        error = "node.advert_name is " + std::to_string(node.name.size()) +
                " bytes; the advert only carries " + std::to_string(budget) +
                (node.has_location() ? " once node.lat/node.lon are set" : "") +
                ", and a longer one fails signature verification on every MeshCore node";
        return false;
    }
    return true;
}

std::vector<std::string_view> Config::keys() {
    Config cfg;
    Raw raw;
    std::vector<std::string_view> out;
    for (const Setting& s : settings(cfg, raw))
        if (!app_key(s.key)) out.push_back(s.key);
    return out;
}

bool Config::app_key(std::string_view key) {
    return std::find(std::begin(kAppKeys), std::end(kAppKeys), key) != std::end(kAppKeys);
}

std::vector<std::string_view> Config::app_keys() {
    return {std::begin(kAppKeys), std::end(kAppKeys)};
}

std::string Config::get(std::string_view key) const {
    if (!app_key(key)) return {};
    // The table binds to fields it may write, so it is built over a copy.
    Config copy = *this;
    Raw raw;
    for (const Setting& s : settings(copy, raw))
        if (s.key == key) return format(s);
    return {};
}

bool Config::set(std::string_view key, std::string_view value, std::string& error) {
    if (!app_key(key)) {
        error = std::string(key) + " is not a setting an app may change";
        return false;
    }
    // A one-line file, so the value meets exactly the parsing and the checks
    // it would on its own line in the settings file.
    Ini line;
    line.set(std::string(key), std::string(value));
    Raw raw;
    for (const Setting& s : settings(*this, raw))
        if (s.key == key) return apply(line, s, error);
    return false;
}

void Config::finalise() {
    // The queue lives inside Node, so it is the node config that carries the
    // path.
    node.messages_path = messages_path();
}

}  // namespace clt
