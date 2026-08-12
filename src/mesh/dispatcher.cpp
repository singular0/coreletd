#include "mesh/dispatcher.h"

#include <algorithm>

#include "crypto/crypto.h"
#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::mesh {

namespace {
// How long a packet stays in the dedup table. Long enough to cover a flood
// rippling across the mesh and coming back, short enough that a genuine resend
// of the same text later still gets through.
constexpr uint32_t kSeenTtlMs = 60000;

// A queued packet is dropped if it has not gone out within this many seconds
// times its priority — stale traffic is worse than no traffic on a mesh.
constexpr uint32_t kExpiryPerPriorityMs = 10000;

// Random pre-transmit spread, so nodes that heard the same flood do not all
// repeat it in the same instant.
constexpr uint32_t kJitterMs = 400;

// How often to look again when the radio is down. Anything still queued when it
// comes back goes out; anything that expired meanwhile was already dropped.
constexpr uint32_t kRadioDownRecheckMs = 1000;

uint32_t pack_hash(ByteView h) {
    uint32_t v = 0;
    for (size_t i = 0; i < 4 && i < h.size(); i++) v |= static_cast<uint32_t>(h[i]) << (i * 8);
    return v;
}
}  // namespace

Dispatcher::Dispatcher(EventLoop& loop, radio::Radio& radio)
    : loop_(loop), radio_(radio), duty_(radio.params().duty_cycle_pct) {}

bool Dispatcher::start(std::string& error) {
    radio_.set_rx_handler([this](radio::RxPacket&& rx) { on_radio_rx(std::move(rx)); });
    radio_.set_tx_done_handler([this](uint32_t airtime) { on_radio_tx_done(airtime); });

    if (!radio_.begin(loop_, error)) return false;

    // Periodic sweep so the dedup table cannot grow without bound on a busy mesh.
    loop_.add_repeating(kSeenTtlMs, [this] { expire_seen(); });
    return true;
}

void Dispatcher::on_radio_rx(radio::RxPacket&& rx) {
    stats_.rx_total++;
    stats_.last_rssi = rx.rssi;
    stats_.last_snr = rx.snr;

    auto p = proto::Packet::decode(rx.data);
    if (!p) {
        stats_.rx_bad++;
        LOG_DEBUG("rx: undecodable packet (%zu bytes)", rx.data.size());
        return;
    }
    p->rssi = rx.rssi;
    p->snr = rx.snr;
    p->rx_millis = rx.rx_millis;

    if (p->is_flood()) {
        stats_.rx_flood++;
    } else {
        stats_.rx_direct++;
    }

    LOG_DEBUG("rx: %s rssi=%d snr=%.1f", p->describe().c_str(), rx.rssi, rx.snr);

    // The raw hook fires for duplicates too: the app derives repeat counts from
    // seeing the same packet arrive by several routes.
    if (on_raw_rx_) on_raw_rx_(*p, rx.data);

    if (check_and_mark_seen(*p)) {
        stats_.rx_dup++;
        LOG_TRACE("rx: duplicate, dropping");
        return;
    }

    if (on_rx_) on_rx_(std::move(*p));
}

bool Dispatcher::check_and_mark_seen(const proto::Packet& p) {
    uint32_t key = pack_hash(p.dedup_hash());
    uint32_t now = millis();

    auto it = seen_.find(key);
    if (it != seen_.end() && static_cast<int32_t>(it->second - now) > 0) {
        it->second = now + kSeenTtlMs;  // refresh so repeats keep it suppressed
        return true;
    }
    seen_[key] = now + kSeenTtlMs;
    return false;
}

void Dispatcher::expire_seen() {
    uint32_t now = millis();
    std::erase_if(seen_, [now](const auto& kv) {
        return static_cast<int32_t>(kv.second - now) <= 0;
    });
}

bool Dispatcher::send(proto::Packet p, uint8_t priority, uint32_t delay_ms) {
    if (!p.valid()) {
        LOG_ERROR("tx: refusing invalid packet: %s", p.describe().c_str());
        stats_.tx_dropped++;
        return false;
    }

    uint32_t now = millis();

    // Anything we originate must not come back to us as "new" if a neighbour
    // repeats it.
    check_and_mark_seen(p);

    Queued q {std::move(p), priority, now + kExpiryPerPriorityMs * priority,
              now + delay_ms, next_seq_++};

    // Insert by (priority, expiry) so equal priorities go out in the order they
    // will time out, which is FIFO for packets queued together.
    auto pos = std::upper_bound(queue_.begin(), queue_.end(), q, [](const Queued& a, const Queued& b) {
        if (a.priority != b.priority) return a.priority < b.priority;
        if (a.expiry_ms != b.expiry_ms) return static_cast<int32_t>(a.expiry_ms - b.expiry_ms) < 0;
        return a.seq < b.seq;
    });
    queue_.insert(pos, std::move(q));

    pump();
    return true;
}

void Dispatcher::schedule_pump(uint32_t delay_ms) {
    if (pump_scheduled_) return;
    pump_scheduled_ = true;
    loop_.add_timer(delay_ms, [this] {
        pump_scheduled_ = false;
        pump();
    });
}

void Dispatcher::pump() {
    if (queue_.empty()) return;
    if (radio_.tx_busy()) return;  // on_radio_tx_done will pump again

    uint32_t now = millis();

    // Drop anything that expired while waiting.
    while (!queue_.empty() && static_cast<int32_t>(queue_.front().expiry_ms - now) <= 0) {
        LOG_DEBUG("tx: dropping expired %s", queue_.front().packet.describe().c_str());
        queue_.pop_front();
        stats_.tx_dropped++;
    }
    if (queue_.empty()) return;

    // Hold everything while the radio is down (an unpowered chip waiting to be
    // retried, say) rather than hammering send() with nothing to send it to.
    if (!radio_.ready()) {
        schedule_pump(kRadioDownRecheckMs);
        return;
    }

    // Respect the regulatory duty cycle before anything else.
    if (uint32_t wait = duty_.wait_ms(); wait > 0) {
        LOG_WARN("tx: duty cycle at %.1f%%, holding off %u ms", duty_.used_pct(), wait);
        schedule_pump(std::min(wait, 30000u));
        return;
    }

    // Honour the per-packet backoff.
    auto it = std::find_if(queue_.begin(), queue_.end(), [now](const Queued& q) {
        return static_cast<int32_t>(q.not_before_ms - now) <= 0;
    });
    if (it == queue_.end()) {
        int32_t soonest = static_cast<int32_t>(queue_.front().not_before_ms - now);
        for (const auto& q : queue_)
            soonest = std::min(soonest, static_cast<int32_t>(q.not_before_ms - now));
        schedule_pump(soonest > 0 ? static_cast<uint32_t>(soonest) : 1);
        return;
    }

    Queued q = std::move(*it);
    queue_.erase(it);

    Bytes raw = q.packet.encode();
    if (raw.size() > proto::kMaxPacketSize) {
        LOG_ERROR("tx: refusing oversized packet (%zu bytes): %s", raw.size(),
                  q.packet.describe().c_str());
        stats_.tx_dropped++;
        pump();
        return;
    }

    if (!radio_.send(raw)) {
        // Radio became busy underneath us; requeue at the front and retry.
        queue_.push_front(std::move(q));
        schedule_pump(20);
        return;
    }

    stats_.tx_total++;
    if (q.packet.is_flood()) {
        stats_.tx_flood++;
    } else {
        stats_.tx_direct++;
    }
    LOG_DEBUG("tx: %s", q.packet.describe().c_str());
}

void Dispatcher::on_radio_tx_done(uint32_t airtime_ms) {
    stats_.airtime_ms += airtime_ms;
    duty_.record(airtime_ms);

    // Spread out the next transmission a little to avoid lock-step collisions.
    uint8_t r = 0;
    crypto::random_bytes(ByteSpan(&r, 1));
    schedule_pump(1 + (r * kJitterMs) / 255);
}

}  // namespace umc::mesh
