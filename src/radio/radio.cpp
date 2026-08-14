#include "radio/radio.h"

#include <cmath>

#include "util/clock.h"

namespace clt::radio {

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

}  // namespace clt::radio
