#pragma once

#include <array>
#include <functional>
#include <optional>
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

// A reception that failed, with whatever the modem can still say about it.
// The rate alone cannot tell the two causes apart: real traffic arriving too
// weak to decode comes in above the noise with a plausible SNR, while a
// demodulator that locked onto noise reports a signal at the noise floor. The
// numbers are what a link at the edge looks like from the inside, and there is
// no other way to see it — nothing is decoded, so nothing else reports.
struct RxFailure {
    RxError error = RxError::Timeout;
    // Of the reception that failed, when the modem has an estimate. A timeout
    // means nothing arrived at all, so `has_signal` is false and the two
    // numbers are meaningless.
    bool has_signal = false;
    int rssi = 0;
    float snr = 0.0f;
};

// The SX1262's high-power PA, in dBm. The top is also the top of an app's power
// slider, which it builds from what SELF_INFO reports.
inline constexpr int kMinTxPowerDbm = -9;
inline constexpr int kMaxTxPowerDbm = 22;

// The LoRa bandwidths the SX1262 offers, in kHz as the datasheet rounds them.
inline constexpr std::array<double, 10> kBandwidthsKhz = {
    7.81, 10.42, 15.63, 20.83, 31.25, 41.67, 62.5, 125.0, 250.0, 500.0,
};

// The supported bandwidth `khz` names, or nullopt when none is within 1%. Apps
// send whole hertz — 7800 for the datasheet's 7.81 kHz, 41700 for its 41.67 —
// so an exact match cannot be asked of them, and the bandwidths are far enough
// apart that anything within 1% names exactly one. Further off than that is a
// bandwidth the chip does not have, and picking the nearest would be choosing a
// different one: on the air, a mismatch is silence.
std::optional<double> nearest_bandwidth(double khz);

// Defaults are MeshCore's on-air settings. Frequency deliberately has no
// default: the region is a legal question, so the config file or the app must
// state it, and until one does nothing is transmitted.
struct RadioParams {
    double freq_mhz = 0.0;
    double bw_khz = 62.5;
    uint8_t sf = 8;
    // Coding rate denominator: 5 == 4/5, which is MeshCore's own default. The
    // explicit header carries it, so a different value still interoperates —
    // it just costs airtime, here and on every repeater that forwards it.
    uint8_t cr = 5;
    int tx_power_dbm = 22;
    double tcxo_voltage = 1.8;  // 0 == module has no TCXO
    bool dio2_as_rf_switch = true;
    bool rx_boosted_gain = true;
    int current_limit_ma = 140;
    // Regulatory transmit budget, as a percentage of wall time. 100 is no
    // limit, which is what MeshCore's airtime factor of 0 means.
    double duty_cycle_pct = 10.0;

    bool operator==(const RadioParams&) const = default;

    bool has_frequency() const { return freq_mhz > 0; }

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
    // (RadioLibWrapper::preambleLengthForSF), doubling it at SF8 and below
    // where a longer preamble buys reliability, and has no setting for it. Both
    // ends still decode a mismatch — the receiver only needs to catch enough of
    // the preamble to sync — but transmitting 16 into a mesh that transmits 32
    // at our own default SF8 gives away half the sync margin our neighbours
    // have.
    uint16_t preamble_symbols() const { return sf <= 8 ? 32 : 16; }

    // Symbols between the preamble and the header: the sync word plus the start
    // frame delimiter. 4.25 at SF7 and above, 6.25 at SF5 and SF6, which the
    // config permits and which the airtime model has to know about because the
    // duty-cycle budget is computed from it.
    double sfd_symbols() const { return sf <= 6 ? 6.25 : 4.25; }
};

class Radio {
public:
    using RxHandler = std::function<void(RxPacket&&)>;
    using RxErrorHandler = std::function<void(const RxFailure&)>;
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

    // Replaces the parameters, which carry a frequency. A radio that is up
    // retunes at once, or after the transmission in flight if there is one;
    // one that is down, or was never given a frequency, starts from these
    // whenever it comes up. Called before begin() it only replaces them.
    virtual void reconfigure(const RadioParams& params) = 0;

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
    void deliver_rx_error(const RxFailure& f) {
        if (on_rx_error_) on_rx_error_(f);
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

    // The airtime already spent stays counted against the new budget.
    void set_percent(double percent) { percent_ = percent; }

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
