#include "radio/mock_radio.h"

#include <cctype>
#include <fstream>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::radio {

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
