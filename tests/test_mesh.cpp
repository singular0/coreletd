#include <cstdio>
#include <fstream>

#include "crypto/crypto.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/inbox.h"
#include "mesh/node.h"
#include "mesh/state_writer.h"
#include "radio/mock_radio.h"
#include "tests/packet_vectors.h"
#include "tests/test_util.h"

using namespace umc;
using namespace umc::test;
using namespace umc::mesh;
namespace pv = umc::pktvec;

class GatedRadio final : public radio::Radio {
public:
    bool begin(EventLoop&, std::string&) override { return true; }
    bool send(ByteView data) override {
        if (!ready_ || busy_) return false;
        busy_ = true;
        send_count_++;
        last_sent_.assign(data.begin(), data.end());
        return true;
    }
    bool tx_busy() const override { return busy_; }
    bool ready() const override { return ready_; }
    const radio::RadioParams& params() const override { return params_; }
    std::string describe() const override { return "gated test radio"; }

    void set_ready(bool ready) { ready_ = ready; }
    void complete_tx(uint32_t airtime_ms = 1) {
        busy_ = false;
        deliver_tx_done(airtime_ms);
    }
    size_t send_count() const { return send_count_; }
    const Bytes& last_sent() const { return last_sent_; }

private:
    radio::RadioParams params_;
    bool ready_ = false;
    bool busy_ = false;
    size_t send_count_ = 0;
    Bytes last_sent_;
};

static void test_public_channel() {
    Channel pub = Channel::public_channel();
    CHECK(pub.valid());
    CHECK_EQ(pub.secret.size(), size_t {16});
    CHECK_BYTES(pub.secret, from_hex(kPublicChannelKeyHex));

    // The wire identifier is the first byte of SHA-256 over the key.
    Bytes digest = crypto::sha256(pub.secret);
    CHECK_EQ(pub.hash(), digest[0]);

    Channel short_key;
    short_key.secret = {1, 2, 3};
    CHECK(!short_key.valid());
}

static void test_hashtag_channel_derivation() {
    // Anyone who knows the name can derive the key, which is the point.
    Channel a = Channel::from_hashtag("#jokes");
    Channel b = Channel::from_hashtag("#jokes");
    CHECK_BYTES(a.secret, b.secret);
    CHECK_EQ(a.secret.size(), size_t {16});

    Bytes expect = crypto::sha256(to_bytes("#jokes"));
    expect.resize(16);
    CHECK_BYTES(a.secret, expect);

    // The '#' is part of the hashed name.
    Channel c = Channel::from_hashtag("jokes");
    CHECK(c.secret != a.secret);
}

static void test_channel_store_slots() {
    ChannelStore store;
    CHECK(store.at(0) != nullptr);
    CHECK(store.at(0)->valid());  // Public preloaded
    CHECK(store.at(ChannelStore::kMaxChannels) == nullptr);

    Channel jokes = Channel::from_hashtag("#jokes");
    uint8_t hash = jokes.hash();
    store.set(3, jokes);

    auto matches = store.by_hash(hash);
    CHECK(!matches.empty());
    bool found = false;
    for (auto& [index, ch] : matches)
        if (index == 3) found = true;
    CHECK(found);
}

static void test_contact_store_roundtrip() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    CHECK(self.has_value());
    if (!self) return;

    const std::string path = "/tmp/umeshcore_test_contacts";
    ContactStore store(*self, path);
    Bytes pub_b = from_hex(pv::kPubB);

    Contact& c = *store.upsert(pub_b);
    c.name = "Peer";
    c.type = proto::kAdvTypeRepeater;
    c.adv_timestamp = pv::kFixedTime;
    c.last_seen = pv::kFixedTime;
    c.lat_e6 = 51507400;
    c.lon_e6 = -127800;
    c.out_path = {0xaa, 0xbb};
    c.path_known = true;

    CHECK(store.save());
    CHECK(!store.dirty());

    ContactStore reloaded(*self, path);
    CHECK(reloaded.load());
    CHECK_EQ(reloaded.size(), size_t {1});

    const Contact* got = reloaded.find(pub_b);
    CHECK(got != nullptr);
    if (got) {
        CHECK(got->name == "Peer");
        CHECK_EQ(got->type, uint8_t {proto::kAdvTypeRepeater});
        CHECK_EQ(got->adv_timestamp, pv::kFixedTime);
        CHECK_EQ(got->lat_e6, 51507400);
        CHECK_EQ(got->lon_e6, -127800);
        CHECK(got->path_known);
        CHECK_BYTES(got->out_path, (Bytes {0xaa, 0xbb}));
    }
    std::remove(path.c_str());
}

static void test_contact_flood_vs_zero_hop_path_survives_reload() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string path = "/tmp/umeshcore_test_contacts2";
    ContactStore store(*self, path);
    Bytes pub_b = from_hex(pv::kPubB);
    Bytes pub_a = from_hex(pv::kPubA);

    // Zero-hop direct neighbour: empty path but path_known.
    Contact& direct = *store.upsert(pub_b);
    direct.path_known = true;
    direct.out_path.clear();

    // Route unknown: must flood.
    Contact& flood = *store.upsert(pub_a);
    flood.path_known = false;

    CHECK(store.save());

    ContactStore reloaded(*self, path);
    CHECK(reloaded.load());

    const Contact* d = reloaded.find(pub_b);
    const Contact* f = reloaded.find(pub_a);
    CHECK(d != nullptr);
    CHECK(f != nullptr);
    // These two states must not collapse into each other on reload.
    if (d) CHECK(d->path_known && d->out_path.empty());
    if (f) CHECK(!f->path_known);

    std::remove(path.c_str());
}

static void test_contact_load_is_all_or_nothing() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string path = "/tmp/umeshcore_test_contacts_corrupt";
    ContactStore store(*self, path);
    Bytes retained_key = from_hex(pv::kPubB);
    Contact* retained = store.upsert(retained_key);
    if (!retained) return;
    retained->name = "Retained";
    CHECK(store.dirty());

    {
        std::ofstream out(path, std::ios::trunc);
        out << "# umeshcore contacts v1\n";
        out << pv::kPubA << "\t1\t0\t100\t100\t0\t0\t-\tNew\n";
        // The old loader silently narrowed this to uint8_t and accepted the
        // first record, replacing the live store with partial state.
        out << pv::kPubB << "\t256\t0\t100\t100\t0\t0\t-\tBad\n";
    }

    CHECK(!store.load());
    const Contact* still_there = store.find(retained_key);
    CHECK(still_there != nullptr);
    if (still_there) CHECK(still_there->name == "Retained");
    CHECK(store.find(from_hex(pv::kPubA)) == nullptr);
    CHECK(store.dirty());

    // A truncated file with no records must not be mistaken for an
    // intentionally empty store; saves always carry the version header.
    {
        std::ofstream out(path, std::ios::trunc);
    }
    CHECK(!store.load());
    CHECK(store.find(retained_key) != nullptr);
    std::remove(path.c_str());
}

static void test_channel_load_is_all_or_nothing() {
    const std::string path = "/tmp/umeshcore_test_channels_corrupt";
    ChannelStore store(path);
    Channel retained = Channel::from_hashtag("#retained");
    store.set(1, retained);
    CHECK(store.dirty());

    {
        std::ofstream out(path, std::ios::trunc);
        out << "# umeshcore channels v1\n";
        out << "2\t00112233445566778899aabbccddeeff\tNew\n";
        out << "3\tabcd\tShort key\n";
    }

    CHECK(!store.load());
    CHECK(store.at(0) && store.at(0)->valid());
    CHECK(store.at(1) && store.at(1)->secret == retained.secret);
    CHECK(store.at(2) && !store.at(2)->valid());
    CHECK(store.dirty());

    // A completely valid file commits as one replacement; omission of slot 0
    // is an intentional clear, not damage inferred from a partial parse.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# umeshcore channels v1\n";
        out << "2\t00112233445566778899aabbccddeeff\tOnly\n";
    }
    CHECK(store.load());
    CHECK(store.at(0) && !store.at(0)->valid());
    CHECK(store.at(1) && !store.at(1)->valid());
    CHECK(store.at(2) && store.at(2)->valid());
    CHECK(!store.dirty());
    std::remove(path.c_str());
}

static void test_advert_replay_is_rejected() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore store(*self);

    auto packet = proto::Packet::decode(from_hex(pv::kAdvertPacket));
    CHECK(packet.has_value());
    if (!packet) return;
    auto adv = proto::Advert::decode(packet->payload);
    if (!adv) return;
    auto app = proto::AdvertAppData::decode(adv->appdata);
    if (!app) return;

    bool created = false;
    Contact* first = store.apply_advert(*adv, *app, created);
    CHECK(first != nullptr);
    CHECK(created);

    // Replaying the same advert must not update anything.
    created = false;
    CHECK(store.apply_advert(*adv, *app, created) == nullptr);

    // An older advert must also be refused.
    proto::Advert older = *adv;
    older.timestamp = adv->timestamp - 1;
    CHECK(store.apply_advert(older, *app, created) == nullptr);

    // A newer one is accepted and is not reported as a new contact.
    proto::Advert newer = *adv;
    newer.timestamp = adv->timestamp + 1;
    created = true;
    Contact* updated = store.apply_advert(newer, *app, created);
    CHECK(updated != nullptr);
    CHECK(!created);
}

static void test_shared_secret_is_cached_and_symmetric() {
    auto a = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    auto b = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    if (!a || !b) return;

    ContactStore store_a(*a);
    Contact& contact_b = *store_a.upsert(from_hex(pv::kPubB));

    const Bytes& s1 = contact_b.shared_secret(*a);
    const Bytes& s2 = contact_b.shared_secret(*a);
    CHECK_BYTES(s1, from_hex(pv::kSharedAB));
    CHECK_BYTES(s1, s2);

    ContactStore store_b(*b);
    Contact& contact_a = *store_b.upsert(from_hex(pv::kPubA));
    CHECK_BYTES(contact_a.shared_secret(*b), s1);
}

static void test_by_id_returns_all_colliding_contacts() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore store(*self);
    // Two distinct keys sharing a first byte: the daemon must try both when
    // decrypting, since the id is only one byte.
    Bytes k1(32, 0x11);
    Bytes k2(32, 0x22);
    k2[0] = 0x11;
    store.upsert(k1);
    store.upsert(k2);

    CHECK_EQ(store.by_id(0x11).size(), size_t {2});
    CHECK_EQ(store.by_id(0x99).size(), size_t {0});
}

static void test_oversized_encrypted_messages_are_rejected() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    ChannelStore channels;
    EventLoop loop;
    radio::RadioParams params;
    radio::MockRadio radio(params, radio::MockRadio::Options {});
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    // 172 bytes plus the 5-byte text header pad to 192 encrypted bytes,
    // making the direct envelope larger than the 184-byte payload limit.
    SendError err = SendError::None;
    CHECK(!node.send_text(peer, std::string(172, 'x'), proto::kTxtPlain, pv::kFixedTime, &err));
    CHECK(err == SendError::TooLong);
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});

    // Channel text also includes "name: " before encryption.
    CHECK(!node.send_channel_text(0, std::string(172, 'x'), pv::kFixedTime));
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});
}

static void test_failed_store_saves_remain_dirty() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self, "/nonexistent/umeshcore/contacts");
    contacts.upsert(from_hex(pv::kPubB));
    CHECK(contacts.dirty());
    CHECK(!contacts.save());
    CHECK(contacts.dirty());

    ChannelStore channels("/nonexistent/umeshcore/channels");
    channels.set(1, Channel::from_hashtag("#persist"));
    CHECK(channels.dirty());
    CHECK(!channels.save());
    CHECK(channels.dirty());
}

static void test_duty_cycle_includes_candidate_airtime() {
    radio::DutyCycle duty(1.0);  // 36,000 ms per rolling hour
    duty.record(35900);

    CHECK_EQ(duty.wait_ms(100), uint32_t {0});
    CHECK(duty.wait_ms(101) > 0);

    radio::DutyCycle several(1.0);
    several.record(10000);
    several.record(10000);
    several.record(10000);
    CHECK(several.wait_ms(7000) > 0);

    radio::DutyCycle impossible(0.001);  // 36 ms per hour
    CHECK(impossible.wait_ms(37) > 0);
}

static void test_dispatch_result_waits_for_actual_transmission() {
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet first;
    first.type = proto::PayloadType::Ack;
    first.payload = {1, 2, 3, 4};

    bool callback_called = false;
    bool transmitted = false;
    CHECK(dispatcher.send(first, kPriorityDirect, 0, [&](bool sent) {
        callback_called = true;
        transmitted = sent;
    }));
    CHECK(!callback_called);
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});

    // Sending another packet prompts the dispatcher to pump. The original is
    // accepted first, and only then may its owner arm an acknowledgement timer.
    radio.set_ready(true);
    proto::Packet second = first;
    second.payload[0] = 5;
    CHECK(dispatcher.send(std::move(second), kPriorityDirect));
    CHECK(callback_called);
    CHECK(transmitted);
    CHECK_EQ(radio.send_count(), size_t {1});
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
}

static void test_identical_pending_messages_are_coalesced() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    auto first = node.send_text(peer, "same message", proto::kTxtPlain, pv::kFixedTime);
    auto duplicate = node.send_text(peer, "same message", proto::kTxtPlain, pv::kFixedTime);

    CHECK(first.has_value());
    CHECK(duplicate.has_value());
    if (first && duplicate) CHECK_BYTES(*first, *duplicate);
    // The second call joins the existing logical delivery instead of adding a
    // wire duplicate that the receiving dispatcher would discard.
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
}

static void test_earlier_pump_replaces_later_timer() {
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet packet;
    packet.type = proto::PayloadType::Ack;
    packet.payload = {1, 2, 3, 4};

    // Queueing while the radio is down installs a one-second recheck.
    CHECK(dispatcher.send(packet, kPriorityAck));
    radio.set_ready(true);

    // A new send pumps immediately. Completing it requests the normal jittered
    // follow-up (at most 400 ms), which must replace that old one-second timer.
    proto::Packet second = packet;
    second.payload[0] = 5;
    CHECK(dispatcher.send(std::move(second), kPriorityAck));
    CHECK_EQ(radio.send_count(), size_t {1});
    radio.complete_tx();

    loop.add_timer(600, [&loop] { loop.stop(); });
    loop.run();
    CHECK_EQ(radio.send_count(), size_t {2});
}

static void test_dispatch_queue_drops_lowest_priority() {
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio, 2);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet packet;
    packet.type = proto::PayloadType::Ack;
    packet.payload = {1, 2, 3, 4};

    bool low_dropped = false;
    bool urgent_dropped = false;
    CHECK(dispatcher.send(packet, kPriorityAdvert, 0,
                          [&](bool sent) { low_dropped = !sent; }));
    packet.payload[0] = 2;
    CHECK(dispatcher.send(packet, kPriorityAck, 0,
                          [&](bool sent) { urgent_dropped = !sent; }));
    packet.payload[0] = 3;
    CHECK(dispatcher.send(packet, kPriorityDirect));

    CHECK_EQ(dispatcher.queue_depth(), size_t {2});
    CHECK(low_dropped);
    CHECK(!urgent_dropped);
    CHECK_EQ(dispatcher.stats().tx_dropped, uint32_t {1});
}

static void test_pending_send_limit_rejects_new_message() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node::Config cfg;
    cfg.pending_send_limit = 1;
    Node node(loop, dispatcher, *self, contacts, channels, cfg);
    SendError err = SendError::PendingFull;
    CHECK(node.send_text(peer, "first", proto::kTxtPlain, pv::kFixedTime, &err).has_value());
    // A successful send must clear the reason, not leave the caller's variable
    // reading as the previous failure.
    CHECK(err == SendError::None);
    CHECK(!node.send_text(peer, "second", proto::kTxtPlain, pv::kFixedTime + 1, &err).has_value());
    CHECK(err == SendError::PendingFull);
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
}

// The three ways a send can fail have to stay apart all the way to the caller:
// the companion protocol turns each into a different error for the user, and
// telling someone the contact table is full when their message was too long
// sends them to fix the wrong thing.
static void test_unusable_contact_key_is_reported_as_such() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    // All zeros is a small-order point, so no shared secret can be derived —
    // but nothing rejects it on the way into the store, which is how a contact
    // you cannot encrypt for comes to exist.
    Contact& broken = *contacts.upsert(Bytes(crypto::kPubKeySize, 0));
    CHECK(broken.shared_secret(*self).empty());

    ChannelStore channels;
    EventLoop loop;
    radio::RadioParams params;
    radio::MockRadio radio(params, radio::MockRadio::Options {});
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    SendError err = SendError::None;
    CHECK(!node.send_text(broken, "hello", proto::kTxtPlain, pv::kFixedTime, &err));
    CHECK(err == SendError::NoSharedSecret);
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});
}

// A retry is the same send with a higher attempt number, so it has to be built
// by the same code: routed through the contact's path, with a path hash size the
// receiver can parse, and carrying the attempt counter on the wire.
static void test_retry_routes_like_the_first_send() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    const Bytes path = {0xAA, 0xBB};
    contacts.set_path(peer, path);

    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio, 1);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});

    // Keep the radio busy so the message is queued rather than sent at once.
    radio.set_ready(true);
    proto::Packet filler;
    filler.type = proto::PayloadType::Ack;
    filler.payload = {1, 2, 3, 4};
    CHECK(dispatcher.send(filler, kPriorityAck));
    CHECK_EQ(radio.send_count(), size_t {1});

    CHECK(node.send_text(peer, "retry me", proto::kTxtPlain, pv::kFixedTime).has_value());
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
    radio.complete_tx();

    // More urgent traffic displaces it from the one-slot queue. Reporting the
    // send as never transmitted is what schedules the retry.
    proto::Packet urgent = filler;
    urgent.payload[0] = 5;
    CHECK(dispatcher.send(std::move(urgent), kPriorityAck));
    CHECK_EQ(dispatcher.stats().tx_dropped, uint32_t {1});
    radio.complete_tx();

    loop.add_timer(5, [&loop] { loop.stop(); });
    loop.run();

    CHECK_EQ(radio.send_count(), size_t {3});
    auto sent = proto::Packet::decode(radio.last_sent());
    CHECK(sent.has_value());
    if (!sent) return;

    CHECK(sent->is_direct());
    CHECK_EQ(sent->path_hash_size, uint8_t {1});
    CHECK_BYTES(sent->path, path);

    auto env = proto::DirectEnvelope::decode(sent->payload);
    CHECK(env.has_value());
    if (!env) return;
    auto plain = crypto::mac_and_decrypt(peer.shared_secret(*self), env->mac, env->ciphertext);
    CHECK(plain.has_value());
    if (!plain) return;
    auto msg = proto::TextMessage::decode(*plain);
    CHECK(msg.has_value());
    if (!msg) return;
    CHECK_EQ(msg->attempt, uint8_t {1});
    CHECK(msg->body() == "retry me");
}

static void test_contact_references_survive_insertion() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore store(*self);
    Bytes key = from_hex(pv::kPubB);
    Contact& held = *store.upsert(key);
    held.name = "Held";

    // The receive path holds a Contact& across callbacks that may add contacts.
    // Enough insertions here to have reallocated a vector several times over.
    for (uint8_t i = 0; i < 64; i++) store.upsert(Bytes(crypto::kPubKeySize, i));

    CHECK_EQ(store.size(), size_t {65});
    CHECK(&held == store.find(key));
    CHECK(held.name == "Held");
}

// last_seen is persisted state, so anything that updates it has to leave the
// store dirty; otherwise the update is lost unless something else happens to
// save before shutdown.
static void test_received_message_marks_store_dirty() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    if (!self) return;

    const std::string path = "/tmp/umeshcore_test_contacts_touch";
    ContactStore contacts(*self, path);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubA));
    ChannelStore channels;
    EventLoop loop;
    radio::RadioParams params;
    radio::MockRadio radio(params, radio::MockRadio::Options {});
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    // The reference packet is a zero-hop flood, so give the contact that exact
    // route up front: the return path is then unchanged and last_seen is the
    // only reason the store can come out dirty.
    contacts.set_path(peer, {});

    CHECK(contacts.save());
    CHECK(!contacts.dirty());
    std::remove(path.c_str());

    radio.inject(from_hex(pv::kTextPacket));

    CHECK(node.has_messages());
    CHECK(peer.last_seen != 0);
    CHECK(peer.last_rssi != 0);
    CHECK(contacts.dirty());
}

static void test_direct_ack_marks_store_dirty() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string path = "/tmp/umeshcore_test_contacts_ack";
    ContactStore contacts(*self, path);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    ChannelStore channels;
    EventLoop loop;
    radio::RadioParams params;
    radio::MockRadio radio(params, radio::MockRadio::Options {});
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    // Same inputs as the reference text packet, so the ack vector matches.
    auto ack = node.send_text(peer, std::string(pv::kTextBody), proto::kTxtPlain, pv::kFixedTime);
    CHECK(ack.has_value());
    if (ack) CHECK_BYTES(*ack, from_hex(pv::kTextAckHash));

    CHECK(contacts.save());
    CHECK(!contacts.dirty());
    std::remove(path.c_str());

    // A direct-routed ack proves the peer heard us, and updates last_seen.
    radio.inject(from_hex(pv::kAckPacket));

    CHECK(peer.last_seen != 0);
    CHECK(contacts.dirty());
}

// The radio receives whether or not an app is connected, so the inbox is
// bounded and drops the oldest message rather than growing. On its own that
// takes three messages to demonstrate; through a node it took 257 packets.
static void test_inbox_drops_oldest_when_full() {
    MessageInbox inbox(2);
    for (int i = 0; i < 3; i++) {
        StoredMessage m;
        m.text = std::to_string(i);
        inbox.store(std::move(m));
    }
    CHECK_EQ(inbox.size(), size_t {2});

    auto oldest = inbox.pop();
    CHECK(oldest.has_value());
    if (oldest) CHECK(oldest->text == "1");  // "0" was dropped, "1" was not

    CHECK(inbox.pop().has_value());
    CHECK(inbox.empty());
    CHECK(!inbox.pop().has_value());
}

// Companion commands are answered before their state reaches disk, so that an
// app working through its contact list one command at a time costs one durable
// replacement rather than one per contact.
static void test_state_writer_batches_deferred_saves() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string contacts_path = "/tmp/umeshcore_test_writer_contacts";
    const std::string channels_path = "/tmp/umeshcore_test_writer_channels";

    EventLoop loop;
    ContactStore contacts(*self, contacts_path);
    ChannelStore channels(channels_path);
    StateWriter writer(loop, contacts, channels, 5);

    contacts.upsert(from_hex(pv::kPubB));
    writer.request_save();
    channels.set(1, Channel::from_hashtag("#writer"));
    writer.request_save();

    // Neither request wrote anything on its own.
    CHECK(contacts.dirty());
    CHECK(channels.dirty());

    loop.add_timer(30, [&loop] { loop.stop(); });
    loop.run();

    // One pass covers every store that had changed, including the one whose
    // change arrived after the write was already scheduled.
    CHECK(!contacts.dirty());
    CHECK(!channels.dirty());
    CHECK(writer.healthy());

    ContactStore reloaded(*self, contacts_path);
    CHECK(reloaded.load());
    CHECK(reloaded.find(from_hex(pv::kPubB)) != nullptr);

    ChannelStore reloaded_channels(channels_path);
    CHECK(reloaded_channels.load());
    CHECK(reloaded_channels.at(1) && reloaded_channels.at(1)->valid());

    std::remove(contacts_path.c_str());
    std::remove(channels_path.c_str());
}

// Deferring the write means the command that caused it cannot report the
// failure, so an unwritable state directory has to stay visible afterwards.
static void test_state_writer_reports_failed_writes() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    EventLoop loop;
    ContactStore contacts(*self, "/nonexistent/umeshcore/contacts");
    ChannelStore channels("/nonexistent/umeshcore/channels");
    StateWriter writer(loop, contacts, channels);
    CHECK(writer.healthy());

    contacts.upsert(from_hex(pv::kPubB));
    CHECK(!writer.flush());
    CHECK(!writer.healthy());
    // Still dirty, so the next attempt retries instead of losing the change.
    CHECK(contacts.dirty());
}

static void test_contact_limit_rejects_new_but_allows_update() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self, {}, 1);
    Bytes first_key = from_hex(pv::kPubB);
    Contact* first = contacts.upsert(first_key);
    CHECK(first != nullptr);
    CHECK(contacts.upsert(from_hex(pv::kPubA)) == nullptr);
    CHECK(contacts.upsert(first_key) == first);
    CHECK_EQ(contacts.size(), size_t {1});
}

int main() {
    if (!crypto::init()) return 2;

    test_public_channel();
    test_hashtag_channel_derivation();
    test_channel_store_slots();
    test_contact_store_roundtrip();
    test_contact_flood_vs_zero_hop_path_survives_reload();
    test_contact_load_is_all_or_nothing();
    test_channel_load_is_all_or_nothing();
    test_advert_replay_is_rejected();
    test_shared_secret_is_cached_and_symmetric();
    test_by_id_returns_all_colliding_contacts();
    test_oversized_encrypted_messages_are_rejected();
    test_failed_store_saves_remain_dirty();
    test_duty_cycle_includes_candidate_airtime();
    test_dispatch_result_waits_for_actual_transmission();
    test_identical_pending_messages_are_coalesced();
    test_earlier_pump_replaces_later_timer();
    test_dispatch_queue_drops_lowest_priority();
    test_pending_send_limit_rejects_new_message();
    test_unusable_contact_key_is_reported_as_such();
    test_retry_routes_like_the_first_send();
    test_contact_references_survive_insertion();
    test_received_message_marks_store_dirty();
    test_direct_ack_marks_store_dirty();
    test_inbox_drops_oldest_when_full();
    test_state_writer_batches_deferred_saves();
    test_state_writer_reports_failed_writes();
    test_contact_limit_rejects_new_but_allows_update();

    return finish("mesh");
}
