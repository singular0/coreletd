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

// How long MeshCore waits before offering a route again to a contact that is
// still flooding at us (BaseChatMesh::handleReturnPathRetry). A flood-routed
// ack from a peer we hold a route for means our path return never reached it,
// or has not yet; the pause is so the reminder does not land on top of
// whatever is still in flight.
constexpr uint32_t kReturnPathRetryMs = 3000;

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
    // There is no asking a peer for a route outright short of a REQ round
    // trip, and MeshCore takes a route only from a returned path. A flood
    // advert at least makes sure the peer holds us, so the next exchange — our
    // message flooded, its PATH flooded back, our reciprocal one direct — can
    // teach both sides.
    send_advert(true);
    return true;
}

// ---------------------------------------------------------------------------
// Receive
// ---------------------------------------------------------------------------

void Node::on_packet(proto::Packet&& p) {
    // Two direct-routed kinds follow rules of their own, and MeshCore applies
    // them before anything else. A trace's path is not a route at all but the
    // SNR each hop heard it at, so read as one it would send on any trace
    // whose first reading happened to equal our hash. And a control packet
    // with its top bit set is zero-hop only: never forwarded, whatever its
    // path says.
    if (p.is_direct() && p.type == proto::PayloadType::Trace) {
        forward_trace(p);
        return;
    }
    if (p.is_direct() && p.type == proto::PayloadType::Control && !p.payload.empty() &&
        (p.payload[0] & 0x80) != 0) {
        LOG_DEBUG("rx: zero-hop CONTROL not handled by a companion node");
        return;
    }

    // A direct-routed packet with hops still on its path is in transit, not for
    // us, and MeshCore does not so much as try to decrypt one. The exception is
    // an ack, which it reads early out of any packet passing by. If relaying is
    // on and we are the next hop, the packet is ours to send on.
    if (p.is_direct() && p.hop_count() > 0) {
        bool forward = true;
        if (p.type == proto::PayloadType::Ack) forward = handle_ack(p);
        if (forward) forward_direct(p);
        return;
    }

    bool forward = false;
    switch (p.type) {
        case proto::PayloadType::Advert: forward = handle_advert(p); break;
        case proto::PayloadType::TxtMsg: forward = handle_text(p); break;
        case proto::PayloadType::Ack: forward = handle_ack(p); break;
        case proto::PayloadType::Path: forward = handle_path(p); break;
        case proto::PayloadType::GrpTxt:
            handle_group_text(p);
            forward = true;
            break;
        case proto::PayloadType::Req:
        case proto::PayloadType::Response:
        case proto::PayloadType::AnonReq: forward = handle_request(p); break;
        case proto::PayloadType::GrpData:
            // Not decoded by a companion node, but MeshCore floods it onward
            // all the same, whether or not it holds the channel.
            LOG_DEBUG("rx: %s not handled by a companion node",
                      proto::payload_type_name(p.type));
            forward = true;
            break;
        default:
            // TRACE, MULTIPART, CONTROL, RAW_CUSTOM and the reserved types are
            // never flood-routed by MeshCore, so a relay must not either.
            LOG_DEBUG("rx: %s is not flood-routed", proto::payload_type_name(p.type));
            break;
    }
    if (forward) maybe_repeat(p);
}

bool Node::handle_advert(const proto::Packet& p) {
    auto adv = proto::Advert::decode(p.payload);
    if (!adv) return false;

    // Never trust an advert's contents before the signature checks out —
    // otherwise any repeater could rename or relocate a node in flight. Never
    // repeat one either: MeshCore floods an advert onward only once it has
    // verified it, so a relay that passed forgeries along would be the one
    // thing on the mesh amplifying them.
    if (!adv->verify()) {
        LOG_WARN("advert: bad signature from %s, ignoring", hex_prefix(adv->pubkey).c_str());
        return false;
    }
    if (crypto::equal(adv->pubkey, self_.pub())) return false;  // our own advert came back

    // From here on the packet is routed onward whatever we make of its
    // contents, as Mesh::onRecvPacket does once the signature is good.
    auto app = proto::AdvertAppData::decode(adv->appdata);
    if (!app) return true;

    // MeshCore ignores an advert that carries no name
    // (BaseChatMesh::onAdvertRecv), so a contact made from one would be a
    // contact no other node on the mesh holds.
    if (!app->has_name() || app->name.empty() || app->name[0] == '\0') {
        LOG_DEBUG("advert: %s carries no name, ignoring", hex_prefix(adv->pubkey).c_str());
        return true;
    }

    bool created = false;
    Contact* c = contacts_.apply_advert(*adv, *app, created);
    if (!c) return true;  // replay or not newer

    contacts_.touch(*c, p.rssi, p.snr);

    // The path a flood advert accumulated is deliberately not turned into a
    // route: MeshCore takes routes only from returned paths, and so do we. A
    // peer's packet reversed is a guess about links we have never used, and a
    // wrong guess would be installed over a route the peer actually told us.
    LOG_INFO("advert: %s \"%s\" (%s, %zu hops)", hex_prefix(c->pubkey).c_str(), c->name.c_str(),
             created ? "new" : "updated", p.hop_count());

    if (delegate_) {
        delegate_->on_advert_seen(*c);
        delegate_->on_contact_changed(*c, created);
    }
    return true;
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

bool Node::handle_request(const proto::Packet& p) {
    // Nothing here answers a request, but MeshCore opens one addressed to it
    // before deciding whether to flood it on: one that opens was for this node
    // and goes no further, and a relay that repeated it would be sending a
    // peer's request to us back out across the mesh. One that does not open
    // belongs to somebody sharing our first key byte, and goes on.
    bool opened = false;
    if (p.type == proto::PayloadType::AnonReq) {
        auto env = proto::AnonReqEnvelope::decode(p.payload);
        if (!env) return false;  // too short to be one; MeshCore drops it unrouted
        if (env->dest_hash != self_.pub()[0]) return true;
        // Its sender need not be a contact, so the key comes with the packet.
        auto shared = self_.shared_secret(env->pubkey);
        opened = shared && crypto::mac_and_decrypt(*shared, env->mac, env->ciphertext);
    } else {
        auto env = proto::DirectEnvelope::decode(p.payload);
        if (!env) return false;
        if (env->dest_hash != self_.pub()[0]) return true;
        Bytes plaintext;
        opened = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext) != nullptr;
    }
    if (opened) {
        LOG_DEBUG("rx: %s for us, not handled by a companion node",
                  proto::payload_type_name(p.type));
    }
    return !opened;
}

bool Node::handle_text(const proto::Packet& p) {
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env) return false;  // too short to be one; MeshCore drops it unrouted

    // Not addressed to us. Repeaters still forward it; we just do not decrypt.
    if (env->dest_hash != self_.pub()[0]) return true;

    Bytes plaintext;
    Contact* from = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext);
    if (!from) {
        // Somebody else's, sharing our first key byte — or a peer we have not
        // heard an advert from. Either way the mesh still wants it repeated.
        LOG_DEBUG("rx: text for us from unknown contact %02x", env->src_hash);
        return true;
    }

    // Decrypted, so it was for us: MeshCore marks it do-not-retransmit at this
    // point, before it has looked at what kind of text it is.
    auto msg = proto::TextMessage::decode(plaintext);
    if (!msg) return false;

    if (msg->txt_type != proto::kTxtPlain && msg->txt_type != proto::kTxtCliData &&
        msg->txt_type != proto::kTxtSignedPlain) {
        // MeshCore drops these without an ack. A sender of some future kind of
        // text gets silence from a node that cannot read it, rather than an
        // ack computed by a rule the new type may not share.
        LOG_DEBUG("msg: unsupported text type %u from %s, ignoring", msg->txt_type,
                  hex_prefix(from->pubkey).c_str());
        return false;
    }

    contacts_.touch(*from, p.rssi, p.snr);

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
    Bytes ack;
    if (msg->txt_type != proto::kTxtCliData) {
        ByteView ack_key =
            msg->txt_type == proto::kTxtSignedPlain ? self_.pub() : ByteView(from->pubkey);
        ack = proto::ack_payload(proto::message_ack_hash(plaintext, ack_key),
                                 proto::ack_extended_attempt(plaintext));
    }

    // A flood-routed message means the sender has no route to us. Answer with
    // the route it should use — and put the ack inside it, so the reply still
    // costs one transmission rather than two. Without this the sender floods
    // every packet to us for good: it learns a path only from a returned one.
    //
    // The reply is flooded, as MeshCore's is (BaseChatMesh::onPeerDataRecv).
    // We have no route to the sender either: its packet's path reversed is a
    // guess about links we have never used, and when the guess is wrong the
    // sender loses both its ack and the route, and retries down the same hole.
    // Flooded, the reply reaches it by whatever route works, exactly as its
    // message reached us.
    if (p.is_flood()) {
        send_path_return(*from, p, ack.empty() ? 0 : static_cast<uint8_t>(proto::PayloadType::Ack),
                         ack, std::nullopt);
    } else if (!ack.empty()) {
        send_ack(*from, ack);
    }
    return false;
}

void Node::send_ack(const Contact& to, ByteView ack) {
    proto::Packet p;
    p.type = proto::PayloadType::Ack;
    p.payload.assign(ack.begin(), ack.end());

    LOG_DEBUG("ack: sending %s", hex(subview(ack, 0, crypto::kAckHashSize)).c_str());
    route_to(dispatcher_, p, to, kPriorityAck);
}

void Node::send_path_return(const Contact& to, const proto::Packet& inbound, uint8_t extra_type,
                            ByteView extra, std::optional<Via> via, uint32_t delay_ms) {
    const Bytes& shared = to.shared_secret(self_);
    if (shared.empty()) return;  // unusable key; nothing to encrypt with

    proto::PathReturn ret;
    ret.path = inbound.path;
    ret.path_hash_size = inbound.path_hash_size;
    ret.has_extra = true;
    if (!extra.empty()) {
        ret.extra_type = extra_type;
        ret.extra.assign(extra.begin(), extra.end());
    } else {
        // MeshCore fills an empty extra with a dummy type and four random bytes,
        // because two path returns carrying the same route would otherwise be
        // byte-identical and every repeater in between would drop the second as
        // a duplicate. Ours would too: the dedup hash covers the payload.
        ret.extra_type = 0x0F;
        ret.extra.resize(4);
        crypto::random_bytes(ret.extra);
    }

    proto::Packet p;
    p.type = proto::PayloadType::Path;
    p.payload = proto::DirectEnvelope::seal(to.pubkey[0], self_.pub()[0], shared, ret.encode())
                    .encode();
    if (via) {
        p.route = proto::RouteType::Direct;
        p.path = via->path;
        p.path_hash_size = via->hash_size;
    } else {
        p.route = proto::RouteType::Flood;
    }

    LOG_DEBUG("path: returning route %s to %s%s, %s",
              ret.path.empty() ? "direct" : hex(ret.path).c_str(),
              hex_prefix(to.pubkey).c_str(), extra.empty() ? "" : " with an ack inside",
              via ? (via->path.empty() ? "zero-hop" : hex(via->path).c_str()) : "flooded");
    // Ack priority whether or not it carries one: a path return that arrives
    // after the sender has given up and retried has taught it nothing.
    if (!dispatcher_.send(std::move(p), kPriorityAck, delay_ms))
        LOG_WARN("path: return to %s did not fit a packet", hex_prefix(to.pubkey).c_str());
}

Contact* Node::complete_ack(ByteView ack_hash, bool direct, bool& matched) {
    auto done = sender_.complete(ack_hash);
    matched = done.has_value();
    if (!done) {
        LOG_TRACE("ack: %s does not match anything pending", hex(ack_hash).c_str());
        return nullptr;
    }

    // A direct-routed ack proves the path we used still works.
    Contact* c = contacts_.find(done->dest_pubkey);
    if (c && direct) contacts_.touch(*c);

    // Notify the companion with the original hash returned by CMD_SEND_TXT,
    // even when a later retry's attempt-specific hash was acknowledged.
    if (delegate_) delegate_->on_ack(done->ack_hash);
    return c;
}

bool Node::handle_ack(const proto::Packet& p) {
    if (p.payload.size() < crypto::kAckHashSize) return false;

    bool matched = false;
    Contact* c = complete_ack(subview(p.payload, 0, crypto::kAckHashSize), p.is_direct(), matched);
    if (!matched) return true;  // somebody else's; a relay floods it on

    // The peer acked by flooding although we hold a route for it, so it holds
    // none for us: our path return never reached it, or has not yet. MeshCore
    // offers the route again, direct, after a pause for whatever is still in
    // flight to land first.
    if (p.is_flood() && c && c->path_known) {
        send_path_return(*c, p, 0, {}, Via {c->out_path, 1}, kReturnPathRetryMs);
    }
    return false;
}

bool Node::handle_path(const proto::Packet& p) {
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env) return false;
    if (env->dest_hash != self_.pub()[0]) return true;

    Bytes plaintext;
    Contact* from = decrypt_from(env->src_hash, env->mac, env->ciphertext, plaintext);
    if (!from) return true;

    auto path = proto::PathReturn::decode(plaintext);
    if (!path) return true;  // MeshCore rejects the encoding but still floods the packet on

    // Wider hashes are a route we cannot address yet — routing writes 1-byte
    // hops — and storing one would install a path that reaches nobody. The rest
    // of the packet is still worth having.
    if (path->path_hash_size == 1) {
        contacts_.set_path(*from, path->path);
        contacts_.touch(*from);
        LOG_INFO("path: %s returned route %s", hex_prefix(from->pubkey).c_str(),
                 path->path.empty() ? "direct" : hex(path->path).c_str());
        if (delegate_) delegate_->on_path_updated(*from);
    } else {
        LOG_DEBUG("path: %s returned a %u-byte-hash route we cannot use yet",
                  hex_prefix(from->pubkey).c_str(), path->path_hash_size);
    }

    // A returned path can carry an ack rather than costing a second packet.
    if (path->has_extra && path->extra_type == static_cast<uint8_t>(proto::PayloadType::Ack) &&
        path->extra.size() >= crypto::kAckHashSize) {
        bool matched = false;
        complete_ack(subview(path->extra, 0, crypto::kAckHashSize), p.is_direct(), matched);
    }

    // It reached us flood-routed, so the sender has no route to us either.
    // Answer with one — direct, along the route it just gave us, whatever the
    // width of its hashes (Mesh::onRecvPacket sends it down that path as
    // given). Its own reply will arrive direct and stops the exchange there.
    if (p.is_flood()) send_path_return(*from, p, 0, {}, Via {path->path, path->path_hash_size});
    return false;
}

void Node::handle_group_text(const proto::Packet& p) {
    auto env = proto::GroupEnvelope::decode(p.payload);
    if (!env) return;

    for (auto& [index, ch] : channels_.by_hash(env->channel_hash)) {
        auto plain = crypto::mac_and_decrypt(ch->secret, env->mac, env->ciphertext);
        if (!plain) continue;  // hash collision with another channel

        auto msg = proto::TextMessage::decode(*plain);
        if (!msg) continue;

        // MeshCore drops a group text whose type bits are set
        // (BaseChatMesh::onGroupDataRecv): only plain text is defined on a
        // channel, and whatever a future type carries is not for the app as is.
        if (msg->txt_type != proto::kTxtPlain) {
            LOG_DEBUG("channel %zu (%s): unsupported group text type %u, ignoring", index,
                      ch->name.c_str(), msg->txt_type);
            return;
        }

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
    if (!p.is_flood()) return;  // direct packets are forwarded along their path instead
    if (p.hop_count() >= cfg_.max_hops) return;

    proto::Packet out = p;
    // The whole key: push_hop takes as many bytes of it as the packet's hashes
    // are wide, which is what MeshCore appends (Mesh::routeRecvPacket). A
    // one-byte hash would fail to fit a two- or three-byte path and the packet
    // would silently never be repeated.
    if (!out.push_hop(self_.pub())) return;  // path full

    // Stagger the repeat so neighbours that heard the same packet do not all
    // transmit at once.
    uint8_t r = 0;
    crypto::random_bytes(ByteSpan(&r, 1));
    dispatcher_.send(std::move(out), kPriorityRepeat, 100 + (r * 4));
}

void Node::forward_direct(const proto::Packet& p) {
    if (!cfg_.repeat) return;

    const ByteView next = p.first_hop();
    const ByteView ours = subview(self_.pub(), 0, next.size());
    if (next.empty() || !std::equal(next.begin(), next.end(), ours.begin(), ours.end())) {
        return;  // somebody else's hop
    }

    // MeshCore forwards a multipart packet only by re-sending the acks inside
    // it, which a node that does not assemble multipart traffic cannot do.
    if (p.type == proto::PayloadType::Multipart) return;

    proto::Packet out = p;
    out.pop_hop();

    // An ack goes at once, as routeDirectRecvAcks sends it.
    const uint32_t delay_ms =
        p.type == proto::PayloadType::Ack ? 0 : direct_retransmit_delay(out);

    LOG_DEBUG("relay: forwarding %s", out.describe().c_str());
    // Routed traffic is the most urgent thing a relay sends, and MeshCore gives
    // it the same priority as an ack: somebody chose this path, and a packet
    // held behind our own floods is a path that looks dead from both ends.
    dispatcher_.send(std::move(out), kPriorityAck, delay_ms);
}

void Node::forward_trace(const proto::Packet& p) {
    if (!cfg_.repeat) return;

    // tag(4) auth(4) flags(1), then the route the trace is to take, as wide
    // as the flags' low two bits say. The path counts the hops already taken,
    // one SNR byte each, so it is also where in the route the trace has got to.
    constexpr size_t kTraceHeader = 9;
    if (p.payload.size() <= kTraceHeader) return;
    if (p.path_hash_size != 1 || p.path.size() >= proto::kMaxPathSize) return;
    const size_t width = size_t {1} << (p.payload[8] & 0x03);
    const size_t at = kTraceHeader + p.path.size() * width;
    // At the end of its route a trace is for whoever sent it, and a companion
    // node that cannot send one has nobody to hand the result to.
    if (at + width > p.payload.size()) return;
    const ByteView next = subview(p.payload, at, width);
    const ByteView ours = subview(self_.pub(), 0, width);
    if (!std::equal(next.begin(), next.end(), ours.begin(), ours.end())) return;

    proto::Packet out = p;
    // What we heard it at, in quarter-dB steps — the reading a trace exists to
    // collect. Truncated as MeshCore's cast truncates.
    const float quarters = std::clamp(p.snr * 4.0f, -128.0f, 127.0f);
    out.path.push_back(static_cast<uint8_t>(static_cast<int8_t>(quarters)));

    LOG_DEBUG("relay: forwarding %s", out.describe().c_str());
    // Diagnostics rather than traffic: MeshCore queues a trace behind
    // everything, its own adverts included, and so does this.
    const uint32_t delay_ms = direct_retransmit_delay(out);
    dispatcher_.send(std::move(out), kPriorityAdvert, delay_ms);
}

uint32_t Node::direct_retransmit_delay(const proto::Packet& out) {
    // MeshCore's companion spreads a forward over up to one packet's airtime
    // (MyMesh::getDirectRetransmitDelay): two relays sharing a first key byte
    // both think the hop is theirs, and would otherwise key up together.
    const uint32_t airtime = dispatcher_.radio().airtime_ms(out.encode().size());
    uint8_t r = 0;
    crypto::random_bytes(ByteSpan(&r, 1));
    return (r * airtime) / 255;
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
