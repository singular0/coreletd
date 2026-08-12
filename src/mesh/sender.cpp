#include "mesh/sender.h"

#include <algorithm>
#include <iterator>

#include "crypto/crypto.h"
#include "mesh/routing.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::mesh {

namespace {
// Retry schedule for unacked direct messages. MeshCore allows four attempts
// (the attempt number is two bits); the last one escalates to flood routing
// because a stale direct path is the usual reason an ack never arrives.
constexpr uint32_t kRetryDelayMs[] = {8000, 16000, 32000};
constexpr uint8_t kMaxAttempts = 4;
}  // namespace

ReliableSender::ReliableSender(EventLoop& loop, Dispatcher& dispatcher,
                               const crypto::LocalIdentity& self, ContactStore& contacts,
                               size_t pending_limit)
    : loop_(loop),
      dispatcher_(dispatcher),
      self_(self),
      contacts_(contacts),
      pending_limit_(pending_limit) {}

ReliableSender::Pending* ReliableSender::find(uint64_t id) {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [id](const Pending& p) { return p.id == id; });
    return it == pending_.end() ? nullptr : &*it;
}

void ReliableSender::erase(uint64_t id) {
    std::erase_if(pending_, [id](const Pending& p) { return p.id == id; });
}

std::optional<Bytes> ReliableSender::send_attempt(Pending& pending, const Contact& to,
                                                  bool force_flood, SendError* err) {
    const Bytes& shared = to.shared_secret(self_);
    if (shared.empty()) {
        LOG_ERROR("send: no shared secret for %s", hex_prefix(to.pubkey).c_str());
        if (err) *err = SendError::NoSharedSecret;
        return std::nullopt;
    }

    proto::TextMessage msg;
    msg.timestamp = pending.timestamp;
    msg.txt_type = pending.txt_type;
    // The attempt counter goes on the wire so the receiver can tell a retry
    // from a genuine duplicate message.
    msg.attempt = pending.attempt;
    msg.text = to_bytes(pending.text);

    Bytes plaintext = msg.encode();
    // Plain messages are acked against the sender's key; signed/room messages
    // against the recipient's.
    ByteView ack_key =
        pending.txt_type == proto::kTxtSignedPlain ? ByteView(to.pubkey) : self_.pub();
    Bytes ack_hash = proto::message_ack_hash(plaintext, ack_key);

    // Every attempt is acceptable in reply; the first one is the operation's
    // identity, and what the caller was told to wait for.
    if (pending.attempt == 0) pending.ack_hash = ack_hash;
    pending.accepted_ack_hashes.push_back(ack_hash);

    auto env = proto::DirectEnvelope::seal(to.id(), self_.pub()[0], shared, plaintext);
    proto::Packet p;
    p.type = proto::PayloadType::TxtMsg;
    p.payload = env.encode();

    const bool flood = force_flood || !to.path_known;
    LOG_DEBUG("send: attempt %u for %s via %s", pending.attempt + 1,
              hex(pending.ack_hash).c_str(), flood ? "flood" : "path");

    // Everything below works from copies: an idle radio accepts the packet
    // synchronously, so the transmission callback — and any node code it
    // reaches — can run before route_to() returns.
    const Bytes op_hash = pending.ack_hash;
    const size_t text_size = pending.text.size();
    const uint64_t id = pending.id;

    // An unregistered send (CLI data) is never acked, so there is nothing to
    // retry and no result to wait for.
    Dispatcher::TxResultHandler on_result;
    if (id != 0) {
        on_result = [this, id](bool transmitted) { on_tx_result(id, transmitted); };
    }

    if (!route_to(dispatcher_, p, to, kPriorityDirect, flood, std::move(on_result))) {
        LOG_ERROR("send: %s is too long after encryption and padding (%zu bytes)",
                  hex(op_hash).c_str(), text_size);
        if (err) *err = SendError::TooLong;
        return std::nullopt;
    }
    return ack_hash;
}

std::optional<Bytes> ReliableSender::send(const Contact& to, const std::string& text,
                                          uint8_t txt_type, uint32_t timestamp, SendError* err) {
    if (err) *err = SendError::None;

    // CLI data is never acked, so it carries no retry state.
    const bool acked = txt_type != proto::kTxtCliData;

    if (acked) {
        // Exact duplicate sends are one logical delivery. Sending the same wire
        // packet twice would be suppressed by receivers' deduplication anyway,
        // so coalesce it with the operation already waiting for this ACK.
        auto duplicate = std::find_if(pending_.begin(), pending_.end(), [&](const Pending& pd) {
            return pd.dest_pubkey == to.pubkey && pd.timestamp == timestamp &&
                   pd.txt_type == txt_type && pd.text == text;
        });
        if (duplicate != pending_.end()) {
            LOG_DEBUG("send: coalescing duplicate message awaiting ack %s",
                      hex(duplicate->ack_hash).c_str());
            return duplicate->ack_hash;
        }

        if (pending_.size() >= pending_limit_) {
            LOG_WARN("send: pending message limit reached (%zu)", pending_limit_);
            if (err) *err = SendError::PendingFull;
            return std::nullopt;
        }
    }

    Pending pending;
    pending.id = acked ? next_id_++ : 0;
    pending.dest_pubkey = to.pubkey;
    pending.text = text;
    pending.txt_type = txt_type;
    pending.timestamp = timestamp;
    pending.attempt = 0;

    // Register before transmitting: an idle radio can accept the packet
    // synchronously, and the retry timer is armed from the result callback.
    const uint64_t id = pending.id;
    if (acked) pending_.push_back(std::move(pending));
    Pending& slot = acked ? pending_.back() : pending;

    auto ack_hash = send_attempt(slot, to, /*force_flood=*/false, err);
    if (!ack_hash) {
        if (acked) erase(id);
        return std::nullopt;
    }

    LOG_INFO("send: %zu bytes to %s (ack %s)", text.size(),
             to.name.empty() ? hex_prefix(to.pubkey).c_str() : to.name.c_str(),
             hex(*ack_hash).c_str());
    return ack_hash;
}

void ReliableSender::on_tx_result(uint64_t id, bool transmitted) {
    Pending* p = find(id);
    if (!p) return;

    if (transmitted) {
        // The retry delay begins only once this attempt is genuinely on air,
        // not while it is waiting for radio recovery or duty-cycle capacity.
        queue_retry(id);
        return;
    }

    LOG_WARN("send: attempt %u for %s expired before transmission", p->attempt + 1,
             hex(p->ack_hash).c_str());
    // Advance on the next event-loop pass. This avoids re-entering Dispatcher
    // while it is in the middle of dropping an expired queue entry.
    p->timer = loop_.add_timer(1, [this, id] { on_retry(id); });
}

void ReliableSender::queue_retry(uint64_t id) {
    Pending* p = find(id);
    if (!p) return;

    uint32_t delay = kRetryDelayMs[std::min<size_t>(p->attempt, std::size(kRetryDelayMs) - 1)];
    p->timer = loop_.add_timer(delay, [this, id] { on_retry(id); });
}

void ReliableSender::on_retry(uint64_t id) {
    Pending* p = find(id);
    if (!p) return;

    p->attempt++;
    if (p->attempt >= kMaxAttempts) {
        LOG_WARN("send: giving up on %s after %u attempts", hex(p->ack_hash).c_str(),
                 p->attempt);
        erase(id);
        return;
    }

    Contact* to = contacts_.find(p->dest_pubkey);
    if (!to) {
        erase(id);
        return;
    }

    // Final attempt: fall back to flooding, since a stale direct path is the
    // most likely reason we have not been acked.
    const bool last = p->attempt == kMaxAttempts - 1;
    if (!send_attempt(*p, *to, /*force_flood=*/last)) erase(id);
}

std::optional<ReliableSender::Completion> ReliableSender::complete(ByteView ack_hash) {
    auto it = std::find_if(pending_.begin(), pending_.end(), [&](const Pending& pd) {
        return std::any_of(
            pd.accepted_ack_hashes.begin(), pd.accepted_ack_hashes.end(),
            [&](const Bytes& sent_hash) { return crypto::equal(sent_hash, ack_hash); });
    });
    if (it == pending_.end()) return std::nullopt;

    LOG_INFO("ack: %s confirmed after %u attempt(s)", hex(ack_hash).c_str(), it->attempt + 1);
    loop_.cancel_timer(it->timer);

    Completion done {it->ack_hash, it->dest_pubkey};
    pending_.erase(it);
    return done;
}

}  // namespace umc::mesh
