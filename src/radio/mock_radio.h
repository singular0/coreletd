#pragma once

#include <string>
#include <vector>

#include "radio/radio.h"

namespace umc::radio {

// Radio backend for running the daemon without hardware: transmissions are
// logged and discarded, and packets can be replayed from a file of hex lines
// (`#` comments allowed) to exercise the receive path.
//
// This is what makes the daemon testable on a dev machine, and it is the
// fallback when the SX1262 backend is not compiled in.
class MockRadio : public Radio {
public:
    struct Options {
        std::string replay_file;
        uint32_t first_delay_ms = 2000;
        uint32_t interval_ms = 5000;
        bool repeat = false;
    };

    explicit MockRadio(RadioParams params, Options opts);

    bool begin(EventLoop& loop, std::string& error) override;
    bool send(ByteView data) override;
    bool tx_busy() const override { return tx_busy_; }
    const RadioParams& params() const override { return params_; }
    std::string describe() const override;

    // Injects a packet as if it had been received. Also the hook tests use.
    void inject(Bytes data, int rssi = -80, float snr = 6.0f);

private:
    bool load_replay(std::string& error);
    void replay_next();

    RadioParams params_;
    Options opts_;
    EventLoop* loop_ = nullptr;
    std::vector<Bytes> replay_;
    size_t replay_pos_ = 0;
    bool tx_busy_ = false;
};

}  // namespace umc::radio
