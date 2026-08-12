#include "radio/mock_radio.h"

#include <cmath>
#include <cctype>
#include <fstream>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::radio {

// ---------------------------------------------------------------------------
// Airtime / duty cycle (shared by every backend)
// ---------------------------------------------------------------------------

uint32_t Radio::airtime_ms(size_t bytes) const {
    const RadioParams& p = params();
    if (p.sf < 5 || p.bw_khz <= 0) return 0;

    // Standard LoRa time-on-air. MeshCore disables low-data-rate optimisation,
    // so the DE term is zero.
    const double bw_hz = p.bw_khz * 1000.0;
    const double t_sym = std::pow(2.0, p.sf) / bw_hz;  // seconds
    const double t_preamble = (p.preamble + 4.25) * t_sym;

    const int cr = p.cr >= 5 && p.cr <= 8 ? p.cr - 4 : 4;  // 4/(4+cr)
    const double numerator = 8.0 * bytes - 4.0 * p.sf + 28 + 16 /* CRC on */;
    const double denominator = 4.0 * p.sf;  // explicit header, DE = 0
    double n_payload = 8 + std::ceil(numerator / denominator) * (4 + cr);
    if (n_payload < 8) n_payload = 8;

    const double total = t_preamble + n_payload * t_sym;
    return static_cast<uint32_t>(std::ceil(total * 1000.0));
}

void DutyCycle::prune() const {
    uint32_t now = millis();
    std::erase_if(entries_, [now](const Entry& e) {
        return static_cast<int32_t>(now - e.at_ms) > static_cast<int32_t>(kWindowMs);
    });
}

void DutyCycle::record(uint32_t airtime_ms) {
    prune();
    entries_.push_back(Entry {millis(), airtime_ms});
}

double DutyCycle::used_pct() const {
    prune();
    uint64_t total = 0;
    for (const auto& e : entries_) total += e.airtime_ms;
    return 100.0 * static_cast<double>(total) / kWindowMs;
}

uint32_t DutyCycle::wait_ms(uint32_t candidate_airtime_ms) const {
    if (percent_ <= 0 || percent_ >= 100) return 0;
    prune();

    uint64_t total = 0;
    for (const auto& e : entries_) total += e.airtime_ms;

    // Airtime allowed across the whole window.
    const double budget = kWindowMs * percent_ / 100.0;
    if (static_cast<double>(total + candidate_airtime_ms) <= budget) return 0;

    // No amount of waiting can make one packet larger than the whole budget.
    // Keep it held rather than knowingly exceeding the configured limit.
    if (static_cast<double>(candidate_airtime_ms) > budget) return kWindowMs;

    // Wait until enough of the oldest entries have aged out for the candidate,
    // not merely until one entry has gone. Several small transmissions may
    // need to expire before a larger one fits.
    const double excess = static_cast<double>(total + candidate_airtime_ms) - budget;
    uint64_t released = 0;
    const uint32_t now = millis();
    for (const auto& e : entries_) {
        released += e.airtime_ms;
        if (static_cast<double>(released) < excess) continue;

        int32_t elapsed = static_cast<int32_t>(now - e.at_ms);
        int32_t remaining = static_cast<int32_t>(kWindowMs) - elapsed;
        return remaining > 0 ? static_cast<uint32_t>(remaining) : 0;
    }
    return kWindowMs;
}

// ---------------------------------------------------------------------------
// MockRadio
// ---------------------------------------------------------------------------

MockRadio::MockRadio(RadioParams params, Options opts)
    : params_(params), opts_(std::move(opts)) {}

bool MockRadio::begin(EventLoop& loop, std::string& error) {
    loop_ = &loop;
    if (!opts_.replay_file.empty()) {
        if (!load_replay(error)) return false;
        LOG_INFO("mock radio: replaying %zu packets from %s", replay_.size(),
                 opts_.replay_file.c_str());
        loop.add_timer(opts_.first_delay_ms, [this] { replay_next(); });
    }
    LOG_WARN("mock radio in use — nothing is actually transmitted");
    return true;
}

bool MockRadio::load_replay(std::string& error) {
    std::ifstream in(opts_.replay_file);
    if (!in) {
        error = "cannot open replay file " + opts_.replay_file;
        return false;
    }
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        size_t cut = line.find('#');
        if (cut != std::string::npos) line.resize(cut);
        // Tolerate whitespace inside the hex so captures can be pasted in.
        std::string compact;
        for (char c : line)
            if (!isspace(static_cast<unsigned char>(c))) compact.push_back(c);
        if (compact.empty()) continue;

        auto bytes = unhex(compact);
        if (!bytes) {
            error = opts_.replay_file + ":" + std::to_string(lineno) + ": invalid hex";
            return false;
        }
        replay_.push_back(std::move(*bytes));
    }
    return true;
}

void MockRadio::replay_next() {
    if (replay_pos_ >= replay_.size()) {
        if (!opts_.repeat) return;
        replay_pos_ = 0;
    }
    inject(replay_[replay_pos_++]);
    loop_->add_timer(opts_.interval_ms, [this] { replay_next(); });
}

void MockRadio::inject(Bytes data, int rssi, float snr) {
    LOG_DEBUG("mock radio rx %zu bytes: %s", data.size(), hex(data).c_str());
    deliver_rx(RxPacket {std::move(data), rssi, snr, millis()});
}

bool MockRadio::send(ByteView data) {
    if (tx_busy_) return false;
    uint32_t airtime = airtime_ms(data.size());
    LOG_DEBUG("mock radio tx %zu bytes (%u ms airtime): %s", data.size(), airtime,
              hex(data).c_str());

    tx_busy_ = true;
    // Hold the transmitter busy for the real airtime so timing-dependent logic
    // behaves the same as it will on hardware.
    loop_->add_timer(airtime, [this, airtime] {
        tx_busy_ = false;
        deliver_tx_done(airtime);
    });
    return true;
}

std::string MockRadio::describe() const {
    return vformat("mock radio (%.3f MHz, SF%u, BW %.1f kHz, CR 4/%u)", params_.freq_mhz,
                   params_.sf, params_.bw_khz, params_.cr);
}

}  // namespace umc::radio
