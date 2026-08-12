#pragma once

#include <deque>
#include <functional>
#include <unordered_map>

#include "daemon/eventloop.h"
#include "proto/packet.h"
#include "radio/radio.h"

namespace umc::mesh {

// Lower number == goes out sooner. The expiry of a queued packet is derived
// from its priority, so low-priority traffic is dropped rather than delaying
// something urgent when the queue backs up.
inline constexpr uint8_t kPriorityAck = 1;
inline constexpr uint8_t kPriorityResponse = 2;
inline constexpr uint8_t kPriorityDirect = 3;
inline constexpr uint8_t kPriorityFlood = 4;
inline constexpr uint8_t kPriorityRepeat = 5;
inline constexpr uint8_t kPriorityAdvert = 6;

struct DispatcherStats {
    uint32_t rx_total = 0;
    uint32_t rx_dup = 0;
    uint32_t rx_bad = 0;
    uint32_t rx_flood = 0;
    uint32_t rx_direct = 0;
    uint32_t tx_total = 0;
    uint32_t tx_flood = 0;
    uint32_t tx_direct = 0;
    uint32_t tx_dropped = 0;
    uint64_t airtime_ms = 0;
    int last_rssi = 0;
    float last_snr = 0.0f;
};

// Owns the radio: everything that receives or transmits goes through here.
// Handles deduplication, the priority transmit queue, and duty-cycle pacing.
class Dispatcher {
public:
    using RxHandler = std::function<void(proto::Packet&&)>;
    // Called for every packet received, before dedup — the companion app wants
    // to see repeats to compute hop counts and populate its Discover list.
    using RawRxHandler = std::function<void(const proto::Packet&, ByteView raw)>;

    Dispatcher(EventLoop& loop, radio::Radio& radio);

    void set_rx_handler(RxHandler h) { on_rx_ = std::move(h); }
    void set_raw_rx_handler(RawRxHandler h) { on_raw_rx_ = std::move(h); }

    bool start(std::string& error);

    // Queues a packet. `delay_ms` defers the earliest transmit time, used to
    // stagger flood repeats so nearby nodes do not collide.
    // Returns false without queueing when the packet cannot be represented on
    // the wire. Callers that report command success must check this result.
    bool send(proto::Packet p, uint8_t priority, uint32_t delay_ms = 0);

    // True if this packet was already seen recently; records it either way.
    bool check_and_mark_seen(const proto::Packet& p);

    const DispatcherStats& stats() const { return stats_; }
    size_t queue_depth() const { return queue_.size(); }
    radio::Radio& radio() { return radio_; }
    double duty_used_pct() const { return duty_.used_pct(); }

private:
    struct Queued {
        proto::Packet packet;
        uint8_t priority;
        uint32_t expiry_ms;
        uint32_t not_before_ms;
        uint64_t seq;
    };

    void on_radio_rx(radio::RxPacket&& rx);
    void on_radio_tx_done(uint32_t airtime_ms);
    void pump();
    void schedule_pump(uint32_t delay_ms);
    void expire_seen();

    EventLoop& loop_;
    radio::Radio& radio_;
    radio::DutyCycle duty_;

    std::deque<Queued> queue_;
    uint64_t next_seq_ = 0;
    bool pump_scheduled_ = false;

    // dedup hash (4 bytes, packed into a u32) -> expiry in millis
    std::unordered_map<uint32_t, uint32_t> seen_;

    RxHandler on_rx_;
    RawRxHandler on_raw_rx_;
    DispatcherStats stats_;
};

}  // namespace umc::mesh
