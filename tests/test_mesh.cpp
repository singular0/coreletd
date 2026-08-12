#include <cstdio>

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

    Contact& c = store.upsert(pub_b);
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
    Contact& direct = store.upsert(pub_b);
    direct.path_known = true;
    direct.out_path.clear();

    // Route unknown: must flood.
    Contact& flood = store.upsert(pub_a);
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
    Contact& contact_b = store_a.upsert(from_hex(pv::kPubB));

    const Bytes& s1 = contact_b.shared_secret(*a);
    const Bytes& s2 = contact_b.shared_secret(*a);
    CHECK_BYTES(s1, from_hex(pv::kSharedAB));
    CHECK_BYTES(s1, s2);

    ContactStore store_b(*b);
    Contact& contact_a = store_b.upsert(from_hex(pv::kPubA));
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
    Contact& peer = contacts.upsert(from_hex(pv::kPubB));
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

int main() {
    if (!crypto::init()) return 2;

    test_public_channel();
    test_hashtag_channel_derivation();
    test_channel_store_slots();
    test_contact_store_roundtrip();
    test_contact_flood_vs_zero_hop_path_survives_reload();
    test_advert_replay_is_rejected();
    test_shared_secret_is_cached_and_symmetric();
    test_by_id_returns_all_colliding_contacts();
    test_oversized_encrypted_messages_are_rejected();
    test_failed_store_saves_remain_dirty();
    test_duty_cycle_includes_candidate_airtime();
    test_dispatch_result_waits_for_actual_transmission();

    return finish("mesh");
}
