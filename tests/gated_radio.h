#pragma once

// A radio whose every event the test performs by hand: nothing transmits until
// it is made ready, a transmission stays in flight until the test completes it,
// and packets arrive only when the test injects them. Paired with a ManualClock
// that leaves the whole daemon — from the injected frame to the reply bytes —
// running on time the test moves.

#include <string>

#include "radio/radio.h"
#include "util/bytes.h"

namespace clt::test {

class GatedRadio final : public radio::Radio {
public:
    bool begin(EventLoop& loop, std::string&) override {
        loop_ = &loop;
        return true;
    }
    bool send(ByteView data) override {
        if (!ready_ || busy_) return false;
        busy_ = true;
        send_count_++;
        last_sent_.assign(data.begin(), data.end());
        return true;
    }
    bool tx_busy() const override { return busy_; }
    bool ready() const override { return ready_; }
    const radio::RadioParams& params() const override { return params_; }
    std::string describe() const override { return "gated test radio"; }

    void set_ready(bool ready) { ready_ = ready; }
    void complete_tx(uint32_t airtime_ms = 1) {
        busy_ = false;
        deliver_tx_done(airtime_ms);
    }

    // Delivers `data` as if it had just been received. Stamped from the loop's
    // clock, so an injected packet lands on the same timeline as everything it
    // will be compared against.
    void inject(Bytes data, int rssi = -80, float snr = 6.0f) {
        deliver_rx(radio::RxPacket {std::move(data), rssi, snr, loop_ ? loop_->now_ms() : 0});
    }

    size_t send_count() const { return send_count_; }
    const Bytes& last_sent() const { return last_sent_; }

private:
    radio::RadioParams params_;
    EventLoop* loop_ = nullptr;
    bool ready_ = false;
    bool busy_ = false;
    size_t send_count_ = 0;
    Bytes last_sent_;
};

}  // namespace clt::test
