#include <cstdio>
#include <fstream>

#include "crypto/crypto.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/node.h"
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
    bool send(ByteView) override {
        if (!ready_ || busy_) return false;
        busy_ = true;
        send_count_++;
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

private:
    radio::RadioParams params_;
    bool ready_ = false;
    bool busy_ = false;
    size_t send_count_ = 0;
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

    ContactStore store(*self);
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

    const std::string path = "/tmp/umeshcore_test_contacts";
    CHECK(store.save(path));
    CHECK(!store.dirty());

    ContactStore reloaded(*self);
    CHECK(reloaded.load(path));
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

    ContactStore store(*self);
    Bytes pub_b = from_hex(pv::kPubB);
    Bytes pub_a = from_hex(pv::kPubA);

    // Zero-hop direct neighbour: empty path but path_known.
    Contact& direct = *store.upsert(pub_b);
    direct.path_known = true;
    direct.out_path.clear();

    // Route unknown: must flood.
    Contact& flood = *store.upsert(pub_a);
    flood.path_known = false;

    const std::string path = "/tmp/umeshcore_test_contacts2";
    CHECK(store.save(path));

    ContactStore reloaded(*self);
    CHECK(reloaded.load(path));

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

    ContactStore store(*self);
    Bytes retained_key = from_hex(pv::kPubB);
    Contact* retained = store.upsert(retained_key);
    if (!retained) return;
    retained->name = "Retained";
    CHECK(store.dirty());

    const std::string path = "/tmp/umeshcore_test_contacts_corrupt";
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# umeshcore contacts v1\n";
        out << pv::kPubA << "\t1\t0\t100\t100\t0\t0\t-\tNew\n";
        // The old loader silently narrowed this to uint8_t and accepted the
        // first record, replacing the live store with partial state.
        out << pv::kPubB << "\t256\t0\t100\t100\t0\t0\t-\tBad\n";
    }

    CHECK(!store.load(path));
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
    CHECK(!store.load(path));
    CHECK(store.find(retained_key) != nullptr);
    std::remove(path.c_str());
}

static void test_channel_load_is_all_or_nothing() {
    ChannelStore store;
    Channel retained = Channel::from_hashtag("#retained");
    store.set(1, retained);
    CHECK(store.dirty());

    const std::string path = "/tmp/umeshcore_test_channels_corrupt";
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# umeshcore channels v1\n";
        out << "2\t00112233445566778899aabbccddeeff\tNew\n";
        out << "3\tabcd\tShort key\n";
    }

    CHECK(!store.load(path));
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
    CHECK(store.load(path));
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
    CHECK(!node.send_text(peer, std::string(172, 'x'), proto::kTxtPlain, pv::kFixedTime));
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});

    // Channel text also includes "name: " before encryption.
    CHECK(!node.send_channel_text(0, std::string(172, 'x'), pv::kFixedTime));
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});
}

static void test_failed_store_saves_remain_dirty() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    contacts.upsert(from_hex(pv::kPubB));
    CHECK(contacts.dirty());
    CHECK(!contacts.save("/nonexistent/umeshcore/contacts"));
    CHECK(contacts.dirty());

    ChannelStore channels;
    channels.set(1, Channel::from_hashtag("#persist"));
    CHECK(channels.dirty());
    CHECK(!channels.save("/nonexistent/umeshcore/channels"));
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
    CHECK(node.send_text(peer, "first", proto::kTxtPlain, pv::kFixedTime).has_value());
    CHECK(!node.send_text(peer, "second", proto::kTxtPlain, pv::kFixedTime + 1).has_value());
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
}

static void test_contact_limit_rejects_new_but_allows_update() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self, 1);
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
    test_contact_limit_rejects_new_but_allows_update();

    return finish("mesh");
}
