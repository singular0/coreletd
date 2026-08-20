#pragma once

#include <functional>
#include <string>

#include "daemon/eventloop.h"
#include "util/bytes.h"
#include "util/clock.h"

namespace clt::radio {

struct RxPacket {
    Bytes data;
    int rssi = 0;
    float snr = 0.0f;
    uint32_t rx_millis = 0;
};

// Why the demodulator gave up on a reception. There is no payload to hand up,
// but the rate matters: a receiver locking onto preambles it cannot read looks
// exactly like an idle band unless somebody counts these.
enum class RxError { HeaderError, CrcError, Timeout };

// Defaults are MeshCore's on-air settings. Frequency deliberately has no
// default: the region is a legal question, so the config file must state it.
struct RadioParams {
    double freq_mhz = 0.0;
    double bw_khz = 62.5;
    uint8_t sf = 8;
    // Coding rate denominator: 5 == 4/5, which is MeshCore's own default. The
    // explicit header carries it, so a different value still interoperates —
    // it just costs airtime, here and on every repeater that forwards it.
    uint8_t cr = 5;
    int tx_power_dbm = 22;
    uint8_t sync_word = 0x12;  // MeshCore uses the "private" LoRa sync word
    // 0 means "whatever the spreading factor calls for", which is what a
    // MeshCore neighbour uses; see preamble_symbols(). A configured value is an
    // override for a mesh that has agreed on something else.
    uint16_t preamble = 0;
    double tcxo_voltage = 1.8;  // 0 == module has no TCXO
    bool dio2_as_rf_switch = true;
    bool rx_boosted_gain = true;
    int current_limit_ma = 140;
    // Regulatory transmit budget, as a percentage of wall time.
    double duty_cycle_pct = 10.0;

    // Low-data-rate optimisation is part of the physical layer, not a tuning
    // preference: a mismatch is no link at all, in either direction, with a
    // healthy-looking radio at both ends. MeshCore never calls RadioLib's
    // forceLDRO(), so ldroAuto stays true and SX126x::setModulationParams
    // recomputes the bit from the symbol time on every call — on once a symbol
    // reaches 16 ms. Derive it the same way rather than picking a value.
    bool low_data_rate_optimize() const {
        if (sf < 5 || bw_khz <= 0) return false;
        return static_cast<double>(uint32_t {1} << sf) / bw_khz >= 16.0;
    }

    // Preamble length in symbols. MeshCore derives it from the spreading factor
    // rather than fixing it (RadioLibWrapper::preambleLengthForSF), doubling it
    // at SF8 and below where a longer preamble buys reliability. Both ends
    // still decode a mismatch — the receiver only needs to catch enough of the
    // preamble to sync — but transmitting 16 into a mesh that transmits 32 at
    // our own default SF8 gives away half the sync margin our neighbours have.
    uint16_t preamble_symbols() const { return preamble ? preamble : (sf <= 8 ? 32 : 16); }

    // Symbols between the preamble and the header: the sync word plus the start
    // frame delimiter. 4.25 at SF7 and above, 6.25 at SF5 and SF6, which the
    // config permits and which the airtime model has to know about because the
    // duty-cycle budget is computed from it.
    double sfd_symbols() const { return sf <= 6 ? 6.25 : 4.25; }
};

class Radio {
public:
    using RxHandler = std::function<void(RxPacket&&)>;
    using RxErrorHandler = std::function<void(RxError)>;
    using TxDoneHandler = std::function<void(uint32_t airtime_ms)>;

    virtual ~Radio() = default;

    virtual bool begin(EventLoop& loop, std::string& error) = 0;
    virtual void shutdown() {}

    // Starts a transmission. Returns false if one is already in flight; the
    // caller (Dispatcher) is responsible for queueing.
    virtual bool send(ByteView data) = 0;
    virtual bool tx_busy() const = 0;

    // True while a reception is in progress — a preamble or header has been
    // seen and the packet has not finished arriving. Keying up now destroys it
    // at both ends: Sx1262::send() begins with SetStandby, which tears down our
    // own half-received packet, and 22 dBm on top of somebody else's
    // transmission corrupts theirs. Default false, so a backend with no notion
    // of a busy channel simply behaves as it always did.
    virtual bool channel_busy() { return false; }

    // False while the hardware is unusable. begin() succeeding does not imply
    // this: a driver whose chip is unpowered comes up not-ready and goes ready
    // once the chip turns up. Nothing is transmitted while it is false.
    virtual bool ready() const { return true; }

    virtual const RadioParams& params() const = 0;
    virtual std::string describe() const = 0;

    void set_rx_handler(RxHandler h) { on_rx_ = std::move(h); }
    void set_rx_error_handler(RxErrorHandler h) { on_rx_error_ = std::move(h); }
    void set_tx_done_handler(TxDoneHandler h) { on_tx_done_ = std::move(h); }

    // LoRa time-on-air for a payload of `bytes`, used for duty-cycle
    // accounting and for sizing transmit timeouts.
    uint32_t airtime_ms(size_t bytes) const;

protected:
    void deliver_rx(RxPacket&& p) {
        if (on_rx_) on_rx_(std::move(p));
    }
    void deliver_rx_error(RxError e) {
        if (on_rx_error_) on_rx_error_(e);
    }
    void deliver_tx_done(uint32_t airtime) {
        if (on_tx_done_) on_tx_done_(airtime);
    }

private:
    RxHandler on_rx_;
    RxErrorHandler on_rx_error_;
    TxDoneHandler on_tx_done_;
};

// Tracks transmitted airtime over a sliding window and reports how long to wait
// before the next transmission stays inside the configured duty cycle.
class DutyCycle {
public:
    // The window is an hour wide, so the clock has to come from outside for any
    // of this to be observable in a test.
    DutyCycle(const Clock& clock, double percent) : clock_(clock), percent_(percent) {}

    void record(uint32_t airtime_ms);
    // Milliseconds to wait before transmitting a packet with the given airtime;
    // 0 only when that transmission also fits inside the rolling budget.
    uint32_t wait_ms(uint32_t candidate_airtime_ms) const;
    double used_pct() const;

private:
    struct Entry {
        uint32_t at_ms;
        uint32_t airtime_ms;
    };
    static constexpr uint32_t kWindowMs = 3600000;  // one hour

    void prune() const;

    const Clock& clock_;
    double percent_;
    mutable std::vector<Entry> entries_;
};

}  // namespace clt::radio
