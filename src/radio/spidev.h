#pragma once

#include <string>

#include "util/bytes.h"

namespace clt::radio {

// Thin wrapper over the Linux spidev character device.
class SpiDev {
public:
    ~SpiDev();

    bool open(const std::string& path, uint32_t speed_hz, std::string& error);
    void close();
    bool is_open() const { return fd_ >= 0; }

    // Full-duplex transfer. `rx` may be empty for write-only; when both are
    // given they must be the same length.
    bool transfer(ByteView tx, ByteSpan rx);
    bool write(ByteView tx) { return transfer(tx, {}); }

private:
    int fd_ = -1;
    uint32_t speed_hz_ = 0;
};

}  // namespace clt::radio
