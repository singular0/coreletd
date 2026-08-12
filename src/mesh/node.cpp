#include "mesh/node.h"

#include <algorithm>
#include <iterator>

#include "crypto/crypto.h"
#include "util/clock.h"
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

Node::Node(EventLoop& loop, Dispatcher& dispatcher, const crypto::LocalIdentity& self,
           ContactStore& contacts, ChannelStore& channels, Config cfg)
    : loop_(loop),
      dispatcher_(dispatcher),
      self_(self),
      contacts_(contacts),
      channels_(channels),
      cfg_(std::move(cfg)) {}

void Node::start() {
    dispatcher_.set_rx_handler([this](proto::Packet&& p) { on_packet(std::move(p)); });
    dispatcher_.set_raw_rx_handler([this](const proto::Packet& p, ByteView raw) {
        if (delegate_) delegate_->on_raw_rx(p, raw);
    });

    if (cfg_.advert_interval_s > 0) {
        loop_.add_repeating(cfg_.advert_interval_s * 1000, [this] { send_advert(true); });
    }
}

proto::AdvertAppData Node::build_appdata() const {
    proto::AdvertAppData app;
    app.flags = static_cast<uint8_t>(cfg_.adv_type & proto::kAdvTypeMask);
    if (cfg_.has_location) {
        app.flags |= proto::kAdvHasLocation;
        app.lat_e6 = cfg_.lat_e6;
        app.lon_e6 = cfg_.lon_e6;
    }
    if (!cfg_.name.empty()) {
        app.flags |= proto::kAdvHasName;
        app.name = cfg_.name;
    }
    return app;
}

std::optional<proto::Packet> Node::build_advert_packet(bool flood) const {
    if (!clock_is_valid()) {
        // An advert with a bogus timestamp poisons every peer's replay check:
        // they will hold it and ignore our later, correct adverts.
        LOG_WARN("advert: wall clock not set (set the RTC or let the app set time)");
        return std::nullopt;
    }

    proto::Advert adv = proto::Advert::create(self_, unix_now(), build_appdata());

    proto::Packet p;
    p.type = proto::PayloadType::Advert;
    p.route = flood ? proto::RouteType::Flood : proto::RouteType::Direct;
    p.payload = adv.encode();
    return p;
}

void Node::send_advert(bool flood) {
    auto p = build_advert_packet(flood);
    if (!p) return;

    LOG_INFO("advert: sending as \"%s\" (%s)", cfg_.name.c_str(), flood ? "flood" : "zero-hop");
    dispatcher_.send(std::move(*p), kPriorityAdvert);
}

bool Node::route_packet(proto::Packet& p, const Contact& to, uint8_t priority,
                        Dispatcher::TxResultHandler on_result) {
    if (to.path_known) {
        p.route = proto::RouteType::Direct;
        p.path = to.out_path;
        p.path_hash_size = 1;
    } else {
        p.route = proto::RouteType::Flood;
        p.path.clear();
    }
    return dispatcher_.send(std::move(p), priority, 0, std::move(on_result));
}

std::optional<Bytes> Node::send_text(Contact& to, const std::string& text, uint8_t txt_type,
                                     uint32_t timestamp) {
    const Bytes& shared = to.shared_secret(self_);
    if (shared.empty()) {
        LOG_ERROR("send: no shared secret for %s", hex_prefix(to.pubkey).c_str());
        return std::nullopt;
    }

    proto::TextMessage msg;
    msg.timestamp = timestamp;
    msg.txt_type = txt_type;
    msg.attempt = 0;
    msg.text = to_bytes(text);

    Bytes plaintext = msg.encode();
    // Plain messages are acked against the sender's key; signed/room messages
    // against the recipient's.
    ByteView ack_key = txt_type == proto::kTxtSignedPlain ? ByteView(to.pubkey) : self_.pub();
    Bytes ack_hash = proto::message_ack_hash(plaintext, ack_key);

    // Exact duplicate sends are one logical delivery. Sending the same wire
    // packet twice would be suppressed by receivers' deduplication anyway, so
    // coalesce it with the operation already waiting for this ACK.
    if (txt_type != proto::kTxtCliData) {
        auto duplicate = std::find_if(pending_.begin(), pending_.end(), [&](const Pending& pd) {
            return pd.dest_pubkey == to.pubkey && pd.timestamp == timestamp &&
                   pd.txt_type == txt_type && pd.text == text;
        });
        if (duplicate != pending_.end()) {
            LOG_DEBUG("send: coalescing duplicate message awaiting ack %s",
                      hex(duplicate->ack_hash).c_str());
            return duplicate->ack_hash;
        }
    }

    if (txt_type != proto::kTxtCliData && pending_.size() >= cfg_.pending_send_limit) {
        LOG_WARN("send: pending message limit reached (%u)", cfg_.pending_send_limit);
        return std::nullopt;
    }

    auto env = proto::DirectEnvelope::seal(to.id(), self_.pub()[0], shared, plaintext);
    proto::Packet p;
    p.type = proto::PayloadType::TxtMsg;
    p.payload = env.encode();

    // CLI data is never acked, so there is nothing to retry. Acked messages
    // must be registered before route_packet(): an idle radio can accept the
    // packet synchronously and invoke the transmission callback immediately.
    uint64_t pending_id = 0;
    if (txt_type != proto::kTxtCliData) {
        Pending pending;
        pending.id = next_pending_id_++;
        pending_id = pending.id;
        pending.ack_hash = ack_hash;
        pending.accepted_ack_hashes.push_back(ack_hash);
        pending.dest_pubkey = to.pubkey;
        pending.text = text;
        pending.txt_type = txt_type;
        pending.timestamp = timestamp;
        pending.attempt = 0;
        pending_.push_back(std::move(pending));
    }

    Dispatcher::TxResultHandler on_result;
    if (txt_type != proto::kTxtCliData) {
        on_result = [this, pending_id](bool transmitted) {
            on_tx_result(pending_id, transmitted);
        };
    }
    if (!route_packet(p, to, kPriorityDirect, std::move(on_result))) {
        LOG_ERROR("send: message is too long after encryption and padding (%zu bytes)",
                  text.size());
        std::erase_if(pending_,
                      [pending_id](const Pending& pending) { return pending.id == pending_id; });
        return std::nullopt;
    }

    LOG_INFO("send: %zu bytes to %s (ack %s)", text.size(),
             to.name.empty() ? hex_prefix(to.pubkey).c_str() : to.name.c_str(),
             hex(ack_hash).c_str());
    return ack_hash;
}

void Node::on_tx_result(uint64_t pending_id, bool transmitted) {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [pending_id](const Pending& p) { return p.id == pending_id; });
    if (it == pending_.end()) return;  // acked while another callback was pending

    if (transmitted) {
        // The retry delay begins only once this attempt is genuinely on air,
        // not while it is waiting for radio recovery or duty-cycle capacity.
        queue_retry(pending_id);
        return;
    }

    LOG_WARN("send: attempt %u for %s expired before transmission",
             it->attempt + 1, hex(it->ack_hash).c_str());
    // Advance on the next event-loop pass. This avoids re-entering Dispatcher
    // while it is in the middle of dropping an expired queue entry.
    it->timer = loop_.add_timer(1, [this, pending_id] { on_retry(pending_id); });
}

void Node::queue_retry(uint64_t pending_id) {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [pending_id](const Pending& p) { return p.id == pending_id; });
    if (it == pending_.end()) return;

    uint32_t delay = kRetryDelayMs[std::min<size_t>(it->attempt, std::size(kRetryDelayMs) - 1)];
    it->timer = loop_.add_timer(delay, [this, pending_id] { on_retry(pending_id); });
}

void Node::on_retry(uint64_t pending_id) {
    auto it = std::find_if(pending_.begin(), pending_.end(),
                           [pending_id](const Pending& p) { return p.id == pending_id; });
    if (it == pending_.end()) return;  // acked in the meantime

    it->attempt++;
    if (it->attempt >= kMaxAttempts) {
        LOG_WARN("send: giving up on %s after %u attempts", hex(it->ack_hash).c_str(),
                 it->attempt);
        pending_.erase(it);
        return;
    }

    Contact* to = contacts_.find(it->dest_pubkey);
    if (!to) {
        pending_.erase(it);
        return;
    }

    const Bytes& shared = to->shared_secret(self_);
    if (shared.empty()) {
        pending_.erase(it);
        return;
    }

    proto::TextMessage msg;
    msg.timestamp = it->timestamp;
    msg.txt_type = it->txt_type;
    // The attempt counter goes on the wire so the receiver can tell a retry
    // from a genuine duplicate message.
    msg.attempt = it->attempt;
    msg.text = to_bytes(it->text);

    Bytes plaintext = msg.encode();
    ByteView ack_key =
        it->txt_type == proto::kTxtSignedPlain ? ByteView(to->pubkey) : self_.pub();
    Bytes retry_ack_hash = proto::message_ack_hash(plaintext, ack_key);
    it->accepted_ack_hashes.push_back(retry_ack_hash);

    auto env = proto::DirectEnvelope::seal(to->id(), self_.pub()[0], shared, plaintext);
    proto::Packet p;
    p.type = proto::PayloadType::TxtMsg;
    p.payload = env.encode();

    // Final attempt: fall back to flooding, since a stale direct path is the
    // most likely reason we have not been acked.
    bool last = it->attempt == kMaxAttempts - 1;
    if (last || !to->path_known) {
        p.route = proto::RouteType::Flood;
        p.path.clear();
        LOG_DEBUG("send: retry %u for %s via flood", it->attempt,
                  hex(it->ack_hash).c_str());
    } else {
        p.route = proto::RouteType::Direct;
        p.path = to->out_path;
        LOG_DEBUG("send: retry %u for %s via path", it->attempt,
                  hex(it->ack_hash).c_str());
    }
    if (!dispatcher_.send(std::move(p), kPriorityDirect, 0,
                          [this, pending_id](bool transmitted) {
                              on_tx_result(pending_id, transmitted);
                          })) {
        LOG_ERROR("send: retry for %s could not be queued", hex(it->ack_hash).c_str());
        pending_.erase(it);
    }
}

bool Node::send_channel_text(size_t channel_index, const std::string& text, uint32_t timestamp) {
    Channel* ch = channels_.at(channel_index);
    if (!ch || !ch->valid()) {
        LOG_ERROR("send: channel slot %zu is empty", channel_index);
        return false;
    }

    // Channel messages carry the sender's name inline, since there is no
    // per-sender key to identify them by.
    proto::TextMessage msg;
    msg.timestamp = timestamp;
    msg.txt_type = proto::kTxtPlain;
    msg.text = to_bytes(cfg_.name + ": " + text);

    auto env = proto::GroupEnvelope::seal(ch->hash(), ch->secret, msg.encode());
    proto::Packet p;
    p.type = proto::PayloadType::GrpTxt;
    p.route = proto::RouteType::Flood;  // no route to a group
    p.payload = env.encode();

    LOG_INFO("send: channel %zu (%s): %s", channel_index, ch->name.c_str(), text.c_str());
    if (!dispatcher_.send(std::move(p), kPriorityFlood)) {
        LOG_ERROR("send: channel message is too long after encryption and padding (%zu bytes)",
                  text.size());
        return false;
    }
    return true;
}

bool Node::send_path_discovery(Contact& to) {
    // A zero-hop flood advert is the cheapest way to make a neighbour learn a
    // route back to us; a real path request needs a REQ round trip.
    send_advert(true);
    return true;
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

void Node::on_packet(proto::Packet&& p) {
    switch (p.type) {
        case proto::PayloadType::Advert: handle_advert(p); break;
        case proto::PayloadType::TxtMsg: handle_text(p); break;
        case proto::PayloadType::Ack: handle_ack(p); break;
        case proto::PayloadType::Path: handle_path(p); break;
        case proto::PayloadType::GrpTxt: handle_group_text(p); break;
        default:
            LOG_DEBUG("rx: %s not handled by a companion node",
                      proto::payload_type_name(p.type));
            break;
    }
    maybe_repeat(p);
}

void Node::handle_advert(const proto::Packet& p) {
    auto adv = proto::Advert::decode(p.payload);
    if (!adv) return;

    // Never trust an advert's contents before the signature checks out —
    // otherwise any repeater could rename or relocate a node in flight.
    if (!adv->verify()) {
        LOG_WARN("advert: bad signature from %s, ignoring", hex_prefix(adv->pubkey).c_str());
        return;
    }
    if (crypto::equal(adv->pubkey, self_.pub())) return;  // our own advert came back

    auto app = proto::AdvertAppData::decode(adv->appdata);
    if (!app) return;

    bool created = false;
    Contact* c = contacts_.apply_advert(*adv, *app, created);
    if (!c) return;  // replay or not newer

    c->last_rssi = p.rssi;
    c->last_snr = p.snr;

    // A flood advert accumulates the path it travelled; reversed, that is our
    // route back to the sender.
    if (p.is_flood()) record_return_path(*c, p);

    LOG_INFO("advert: %s \"%s\" (%s, %zu hops)", hex_prefix(c->pubkey).c_str(), c->name.c_str(),
             created ? "new" : "updated", p.hop_count());

    if (delegate_) {
        delegate_->on_advert_seen(*c);
        delegate_->on_contact_changed(*c, created);
    }
}

void Node::record_return_path(Contact& c, const proto::Packet& p) {
    // The path lists the hops the packet took to reach us, so the reverse is
    // the route out. Only 1-byte hashes are usable as a return path here.
    if (p.path_hash_size != 1) return;
    if (p.path.size() > cfg_.max_hops) return;

    Bytes reversed(p.path.rbegin(), p.path.rend());
    if (c.path_known && c.out_path == reversed) return;

    c.out_path = std::move(reversed);
    c.path_known = true;
    contacts_.mark_dirty();
    LOG_DEBUG("path: %s now reachable via %s", hex_prefix(c.pubkey).c_str(),
              c.out_path.empty() ? "direct" : hex(c.out_path).c_str());
    if (delegate_) delegate_->on_path_updated(c);
}

Contact* Node::decrypt_from(uint8_t src_hash, ByteView mac, ByteView ciphertext,
                            Bytes& plaintext) {
    // Several contacts can share a first key byte, so try each until the MAC
    // verifies. That MAC check is also what proves the sender's identity.
    for (Contact* c : contacts_.by_id(src_hash)) {
        const Bytes& shared = c->shared_secret(self_);
        if (shared.empty()) continue;
        if (auto plain = crypto::mac_and_decrypt(shared, mac, ciphertext)) {
            plaintext = std::move(*plain);
            return c;
        }
    }
    return nullptr;
}

void Node::handle_text(const proto::Packet& p) {
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env) return;

    // Not addressed to us. Repeaters still forward it; we just do not decrypt.
    if (env->dest_hash != self_.pub()[0]) return;

    Bytes plaintext;
    Contact* from = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext);
    if (!from) {
        LOG_DEBUG("rx: text for us from unknown contact %02x", env->src_hash);
        return;
    }

    auto msg = proto::TextMessage::decode(plaintext);
    if (!msg) return;

    from->last_seen = unix_now();
    from->last_rssi = p.rssi;
    from->last_snr = p.snr;
    if (p.is_flood()) record_return_path(*from, p);

    const std::string body = msg->body();
    const std::string sender = from->name.empty() ? hex_prefix(from->pubkey) : from->name;
    LOG_INFO("msg from %s (%zu bytes)", sender.c_str(), body.size());
    LOG_TRACE("msg from %s: %s", sender.c_str(), body.c_str());

    StoredMessage stored;
    stored.is_channel = false;
    stored.sender_pubkey = from->pubkey;
    stored.timestamp = msg->timestamp;
    stored.txt_type = msg->txt_type;
    stored.text = body;
    stored.snr_q4 = static_cast<int8_t>(std::clamp(p.snr * 4.0f, -128.0f, 127.0f));
    stored.path_len = p.is_flood() ? 0xFF : static_cast<uint8_t>(p.hop_count());
    store_message(std::move(stored));

    // CLI responses are never acked.
    if (msg->txt_type != proto::kTxtCliData) {
        ByteView ack_key =
            msg->txt_type == proto::kTxtSignedPlain ? self_.pub() : ByteView(from->pubkey);
        send_ack(*from, proto::message_ack_hash(plaintext, ack_key));
    }
}

void Node::send_ack(const Contact& to, ByteView ack_hash) {
    proto::Packet p;
    p.type = proto::PayloadType::Ack;
    p.payload.assign(ack_hash.begin(), ack_hash.end());

    if (to.path_known) {
        p.route = proto::RouteType::Direct;
        p.path = to.out_path;
    } else {
        p.route = proto::RouteType::Flood;
    }
    LOG_DEBUG("ack: sending %s", hex(ack_hash).c_str());
    dispatcher_.send(std::move(p), kPriorityAck);
}

void Node::handle_ack(const proto::Packet& p) {
    if (p.payload.size() < crypto::kAckHashSize) return;
    ByteView ack_hash = subview(p.payload, 0, crypto::kAckHashSize);

    auto it = std::find_if(pending_.begin(), pending_.end(), [&](const Pending& pd) {
        return std::any_of(pd.accepted_ack_hashes.begin(), pd.accepted_ack_hashes.end(),
                           [&](const Bytes& sent_hash) {
                               return crypto::equal(sent_hash, ack_hash);
                           });
    });
    if (it == pending_.end()) {
        LOG_TRACE("ack: %s does not match anything pending", hex(ack_hash).c_str());
        return;
    }

    LOG_INFO("ack: %s confirmed after %u attempt(s)", hex(ack_hash).c_str(), it->attempt + 1);
    loop_.cancel_timer(it->timer);

    // A direct-routed ack proves the path we used still works.
    if (Contact* c = contacts_.find(it->dest_pubkey); c && p.is_direct()) {
        c->last_seen = unix_now();
    }

    // Notify the companion with the original hash returned by CMD_SEND_TXT,
    // even when a later retry's attempt-specific hash was acknowledged.
    Bytes hash_copy = it->ack_hash;
    pending_.erase(it);
    if (delegate_) delegate_->on_ack(hash_copy);
}

void Node::handle_path(const proto::Packet& p) {
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env || env->dest_hash != self_.pub()[0]) return;

    Bytes plaintext;
    Contact* from = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext);
    if (!from) return;

    auto path = proto::PathReturn::decode(plaintext);
    if (!path) return;

    from->out_path = path->path;
    from->path_known = true;
    from->last_seen = unix_now();
    contacts_.mark_dirty();
    LOG_INFO("path: %s returned route %s", hex_prefix(from->pubkey).c_str(),
             path->path.empty() ? "direct" : hex(path->path).c_str());
    if (delegate_) delegate_->on_path_updated(*from);

    // A returned path can carry an ack rather than costing a second packet.
    if (path->has_extra && path->extra_type == static_cast<uint8_t>(proto::PayloadType::Ack) &&
        path->extra.size() >= crypto::kAckHashSize) {
        proto::Packet fake;
        fake.type = proto::PayloadType::Ack;
        fake.route = p.route;
        fake.payload.assign(path->extra.begin(),
                            path->extra.begin() + crypto::kAckHashSize);
        handle_ack(fake);
    }
}

void Node::handle_group_text(const proto::Packet& p) {
    auto env = proto::GroupEnvelope::decode(p.payload);
    if (!env) return;

    for (auto& [index, ch] : channels_.by_hash(env->channel_hash)) {
        auto plain = crypto::mac_and_decrypt(ch->secret, env->mac, env->ciphertext);
        if (!plain) continue;  // hash collision with another channel

        auto msg = proto::TextMessage::decode(*plain);
        if (!msg) continue;

        const std::string body = msg->body();
        LOG_INFO("channel %zu (%s): %zu bytes", index, ch->name.c_str(), body.size());
        LOG_TRACE("channel %zu (%s): %s", index, ch->name.c_str(), body.c_str());

        StoredMessage stored;
        stored.is_channel = true;
        stored.channel_index = static_cast<uint8_t>(index);
        stored.timestamp = msg->timestamp;
        stored.txt_type = msg->txt_type;
        stored.text = body;
        stored.snr_q4 = static_cast<int8_t>(std::clamp(p.snr * 4.0f, -128.0f, 127.0f));
        stored.path_len = p.is_flood() ? 0xFF : static_cast<uint8_t>(p.hop_count());
        store_message(std::move(stored));
        return;
    }
}

void Node::maybe_repeat(const proto::Packet& p) {
    if (!cfg_.repeat) return;
    if (!p.is_flood()) return;  // direct packets are only forwarded along their path
    if (p.hop_count() >= cfg_.max_hops) return;

    proto::Packet out = p;
    Bytes id = {self_.pub()[0]};
    if (!out.push_hop(id)) return;  // path full

    // Stagger the repeat so neighbours that heard the same packet do not all
    // transmit at once.
    uint8_t r = 0;
    crypto::random_bytes(ByteSpan(&r, 1));
    dispatcher_.send(std::move(out), kPriorityRepeat, 100 + (r * 4));
}

void Node::store_message(StoredMessage msg) {
    messages_.push_back(std::move(msg));
    // Bound the queue: if the app never collects, drop the oldest rather than
    // grow without limit.
    while (messages_.size() > cfg_.message_queue_limit) {
        LOG_WARN("message queue full, dropping oldest");
        messages_.pop_front();
    }
    if (delegate_) delegate_->on_message_stored();
}

std::optional<StoredMessage> Node::pop_message() {
    if (messages_.empty()) return std::nullopt;
    StoredMessage m = std::move(messages_.front());
    messages_.pop_front();
    return m;
}

}  // namespace umc::mesh
