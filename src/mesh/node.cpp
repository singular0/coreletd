#include "mesh/node.h"

#include <algorithm>

#include "crypto/crypto.h"
#include "mesh/routing.h"
#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace clt::mesh {

// Long enough to outlast any sender's retry ladder: ours runs 8/16/32 seconds
// and escalates to flood on the last, and MeshCore's is in the same range.
constexpr uint32_t kDeliveredTtlMs = 300000;
// A hard ceiling as well as the sweep, so a mesh busier than the sweep interval
// still cannot grow the table without limit.
constexpr size_t kMaxDelivered = 512;

namespace {

// What the companion protocol calls a message's path_len, MeshCore's way round
// (MyMesh::queueMessage): the packed path_length byte for a flood-routed
// packet, and 0xFF for a direct-routed one. Clients read it that way — the
// Python client tests `plen == 255` for direct and splits the rest into hash
// mode and hop count — so the flood branch has to carry the whole byte, and the
// hop count is useless here anyway: a direct packet arrives with an empty path,
// because every hop pops itself off on the way.
uint8_t companion_path_len(const proto::Packet& p) {
    return p.is_flood() ? p.packed_path_len() : 0xFF;
}

}  // namespace

Node::Node(EventLoop& loop, Dispatcher& dispatcher, const crypto::LocalIdentity& self,
           ContactStore& contacts, ChannelStore& channels, Config cfg)
    : loop_(loop),
      dispatcher_(dispatcher),
      self_(self),
      contacts_(contacts),
      channels_(channels),
      cfg_(std::move(cfg)),
      sender_(loop, dispatcher, self, contacts, cfg_.pending_send_limit),
      inbox_(cfg_.message_queue_limit, cfg_.messages_path) {}

void Node::start() {
    dispatcher_.set_rx_handler([this](proto::Packet&& p) { on_packet(std::move(p)); });
    dispatcher_.set_raw_rx_handler([this](const proto::Packet& p, ByteView raw) {
        if (delegate_) delegate_->on_raw_rx(p, raw);
    });

    if (cfg_.advert_interval_s > 0) {
        advert_timer_ =
            loop_.add_repeating(cfg_.advert_interval_s * 1000, [this] { send_advert(true); });
    }
    // Bounds the table of messages already handed to the app.
    delivered_sweep_ = loop_.add_repeating(kDeliveredTtlMs, [this] { expire_delivered(); });
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

    contacts_.touch(*c, p.rssi, p.snr);

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
    if (!contacts_.set_path(c, reversed)) return;  // route unchanged

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

    contacts_.touch(*from, p.rssi, p.snr);
    if (p.is_flood()) record_return_path(*from, p);

    const std::string body = msg->body();
    const std::string sender = from->name.empty() ? hex_prefix(from->pubkey) : from->name;
    LOG_INFO("msg from %s (%zu bytes)", sender.c_str(), body.size());
    LOG_TRACE("msg from %s: %s", sender.c_str(), body.c_str());

    // A retry is acked like any other copy — the sender is retrying precisely
    // because it did not hear the first ack — but it is only delivered once.
    if (first_delivery(*from, *msg)) {
        StoredMessage stored;
        stored.is_channel = false;
        stored.sender_pubkey = from->pubkey;
        stored.timestamp = msg->timestamp;
        stored.txt_type = msg->txt_type;
        stored.text = body;
        stored.snr_q4 = static_cast<int8_t>(std::clamp(p.snr * 4.0f, -128.0f, 127.0f));
        stored.path_len = companion_path_len(p);
        store_message(std::move(stored));
    } else {
        LOG_DEBUG("msg: attempt %u repeats one already delivered, acking again", msg->attempt);
    }

    // CLI responses are never acked.
    if (msg->txt_type != proto::kTxtCliData) {
        ByteView ack_key =
            msg->txt_type == proto::kTxtSignedPlain ? self_.pub() : ByteView(from->pubkey);
        send_ack(*from, proto::message_ack_hash(plaintext, ack_key),
                 proto::ack_extended_attempt(plaintext));
    }
}

void Node::send_ack(const Contact& to, ByteView ack_hash, uint8_t extended_attempt) {
    proto::Packet p;
    p.type = proto::PayloadType::Ack;
    p.payload = proto::ack_payload(ack_hash, extended_attempt);

    LOG_DEBUG("ack: sending %s", hex(ack_hash).c_str());
    route_to(dispatcher_, p, to, kPriorityAck);
}

void Node::handle_ack(const proto::Packet& p) {
    if (p.payload.size() < crypto::kAckHashSize) return;
    ByteView ack_hash = subview(p.payload, 0, crypto::kAckHashSize);

    auto done = sender_.complete(ack_hash);
    if (!done) {
        LOG_TRACE("ack: %s does not match anything pending", hex(ack_hash).c_str());
        return;
    }

    // A direct-routed ack proves the path we used still works.
    if (Contact* c = contacts_.find(done->dest_pubkey); c && p.is_direct()) {
        contacts_.touch(*c);
    }

    // Notify the companion with the original hash returned by CMD_SEND_TXT,
    // even when a later retry's attempt-specific hash was acknowledged.
    if (delegate_) delegate_->on_ack(done->ack_hash);
}

void Node::handle_path(const proto::Packet& p) {
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env || env->dest_hash != self_.pub()[0]) return;

    Bytes plaintext;
    Contact* from = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext);
    if (!from) return;

    auto path = proto::PathReturn::decode(plaintext);
    if (!path) return;

    contacts_.set_path(*from, path->path);
    contacts_.touch(*from);
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
        stored.path_len = companion_path_len(p);
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

bool Node::first_delivery(const Contact& from, const proto::TextMessage& msg) {
    // Identity is everything the sender would have to change to make this a
    // different message. The attempt number is deliberately not part of it —
    // that is exactly what differs between a retry and the original.
    Bytes id;
    id.reserve(from.pubkey.size() + 5 + msg.text.size());
    put_bytes(id, from.pubkey);
    put_u32(id, msg.timestamp);
    id.push_back(msg.txt_type);
    put_bytes(id, msg.text);

    const Bytes digest = crypto::sha256(id);
    uint64_t key = 0;
    for (size_t i = 0; i < 8 && i < digest.size(); i++)
        key = (key << 8) | digest[i];

    const uint32_t now = loop_.now_ms();
    auto it = delivered_.find(key);
    if (it != delivered_.end() && static_cast<int32_t>(it->second - now) > 0) {
        // Refresh, so a sender still retrying keeps it suppressed.
        it->second = now + kDeliveredTtlMs;
        return false;
    }

    if (delivered_.size() >= kMaxDelivered) {
        expire_delivered();
        // Still full means everything in it is live; drop one rather than grow.
        if (delivered_.size() >= kMaxDelivered) delivered_.erase(delivered_.begin());
    }
    delivered_[key] = now + kDeliveredTtlMs;
    return true;
}

void Node::expire_delivered() {
    const uint32_t now = loop_.now_ms();
    std::erase_if(delivered_, [now](const auto& kv) {
        return static_cast<int32_t>(kv.second - now) <= 0;
    });
}

void Node::store_message(StoredMessage msg) {
    // A failed commit is reported but the message is still queued and still
    // acked: it is in memory either way, and refusing the ack would make the
    // sender retry into a daemon whose disk is the actual problem.
    if (!inbox_.store(std::move(msg))) LOG_ERROR("msg: queued but not persisted");
    if (delegate_) delegate_->on_message_stored();
}

}  // namespace clt::mesh
