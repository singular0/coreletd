#include <cstdio>
#include <fstream>
#include <optional>

#include "crypto/crypto.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/inbox.h"
#include "mesh/node.h"
#include "mesh/state_writer.h"
#include "tests/gated_radio.h"
#include "tests/packet_vectors.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;
using namespace clt::mesh;
namespace pv = clt::pktvec;

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

    const std::string path = "/tmp/coreletd_test_contacts";
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
    CHECK(reloaded.load() == LoadResult::Loaded);
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

    const std::string path = "/tmp/coreletd_test_contacts2";
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
    CHECK(reloaded.load() == LoadResult::Loaded);

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

    const std::string path = "/tmp/coreletd_test_contacts_corrupt";
    ContactStore store(*self, path);
    Bytes retained_key = from_hex(pv::kPubB);
    Contact* retained = store.upsert(retained_key);
    if (!retained) return;
    retained->name = "Retained";
    CHECK(store.dirty());

    {
        std::ofstream out(path, std::ios::trunc);
        out << "# coreletd contacts v1\n";
        out << pv::kPubA << "\t1\t0\t100\t100\t0\t0\t-\tNew\n";
        // The old loader silently narrowed this to uint8_t and accepted the
        // first record, replacing the live store with partial state.
        out << pv::kPubB << "\t256\t0\t100\t100\t0\t0\t-\tBad\n";
    }

    CHECK(store.load() == LoadResult::Corrupt);
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
    CHECK(store.load() == LoadResult::Corrupt);
    CHECK(store.find(retained_key) != nullptr);
    std::remove(path.c_str());
}

static void test_channel_load_is_all_or_nothing() {
    const std::string path = "/tmp/coreletd_test_channels_corrupt";
    ChannelStore store(path);
    Channel retained = Channel::from_hashtag("#retained");
    store.set(1, retained);
    CHECK(store.dirty());

    {
        std::ofstream out(path, std::ios::trunc);
        out << "# coreletd channels v1\n";
        out << "2\t00112233445566778899aabbccddeeff\tNew\n";
        out << "3\tabcd\tShort key\n";
    }

    CHECK(store.load() == LoadResult::Corrupt);
    CHECK(store.at(0) && store.at(0)->valid());
    CHECK(store.at(1) && store.at(1)->secret == retained.secret);
    CHECK(store.at(2) && !store.at(2)->valid());
    CHECK(store.dirty());

    // A completely valid file commits as one replacement; omission of slot 0
    // is an intentional clear, not damage inferred from a partial parse.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# coreletd channels v1\n";
        out << "2\t00112233445566778899aabbccddeeff\tOnly\n";
    }
    CHECK(store.load() == LoadResult::Loaded);
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
    GatedRadio radio;
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

    ContactStore contacts(*self, "/nonexistent/coreletd/contacts");
    contacts.upsert(from_hex(pv::kPubB));
    CHECK(contacts.dirty());
    CHECK(!contacts.save());
    CHECK(contacts.dirty());

    ChannelStore channels("/nonexistent/coreletd/channels");
    channels.set(1, Channel::from_hashtag("#persist"));
    CHECK(channels.dirty());
    CHECK(!channels.save());
    CHECK(channels.dirty());
}

static void test_duty_cycle_includes_candidate_airtime() {
    ManualClock clock;
    radio::DutyCycle duty(clock, 1.0);  // 36,000 ms per rolling hour
    duty.record(35900);

    CHECK_EQ(duty.wait_ms(100), uint32_t {0});
    CHECK(duty.wait_ms(101) > 0);

    radio::DutyCycle several(clock, 1.0);
    several.record(10000);
    several.record(10000);
    several.record(10000);
    CHECK(several.wait_ms(7000) > 0);

    radio::DutyCycle impossible(clock, 0.001);  // 36 ms per hour
    CHECK(impossible.wait_ms(37) > 0);
}

static void test_duty_cycle_budget_returns_with_the_window() {
    // The window is an hour wide. Only a clock we drive makes the far edge of
    // it reachable at all.
    ManualClock clock;
    radio::DutyCycle duty(clock, 1.0);  // 36,000 ms per rolling hour

    duty.record(36000);  // the entire budget, spent at t=0
    CHECK(duty.wait_ms(1000) > 0);
    CHECK_EQ(duty.used_pct(), 1.0);

    // Still spent a second before that transmission ages out, and the wait it
    // reports is exactly the time left on it.
    clock.advance(3599000);
    CHECK_EQ(duty.wait_ms(1000), uint32_t {1000});

    clock.advance(2000);
    CHECK_EQ(duty.wait_ms(1000), uint32_t {0});
    CHECK_EQ(duty.used_pct(), 0.0);
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

// A desensitised receiver and an idle band both deliver no packets. What tells
// them apart is the count of receptions the modem began and could not finish,
// so those must reach the statistics rather than being dropped in the driver.
static void test_failed_receptions_are_counted_separately() {
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    radio.inject_error(radio::RxError::HeaderError);
    radio.inject_error(radio::RxError::HeaderError);
    radio.inject_error(radio::RxError::CrcError);
    radio.inject_error(radio::RxError::Timeout);

    const auto& s = dispatcher.stats();
    CHECK_EQ(s.rx_header_err, uint32_t {2});
    CHECK_EQ(s.rx_crc_err, uint32_t {1});
    CHECK_EQ(s.rx_timeout, uint32_t {1});
    // Nothing was demodulated, so none of this counts as a packet heard.
    CHECK_EQ(s.rx_total, uint32_t {0});
    CHECK_EQ(s.rx_bad, uint32_t {0});
}

// The counts alone cannot say which kind of failure a run of them was: traffic
// arriving too weak to decode and a demodulator chasing noise produce the same
// tally and want opposite answers. The signal the modem measured is the only
// thing that separates them, and nothing else reports it — the packet never
// reached the stack.
static void test_failed_receptions_carry_the_signal_they_failed_at() {
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    radio.inject_error(radio::RxError::CrcError, -106, -14.2f);
    const auto& s = dispatcher.stats();
    CHECK_EQ(s.last_failed_rssi, -106);
    CHECK(s.last_failed_snr < -14.0f && s.last_failed_snr > -14.5f);

    // A header error carries it too: the modem measured what it gave up on.
    radio.inject_error(radio::RxError::HeaderError, -92, -9.0f);
    CHECK_EQ(s.last_failed_rssi, -92);

    // A timeout means nothing arrived at all, so there is nothing to measure
    // and the last real measurement must not be overwritten with a stale one.
    radio.inject_error(radio::RxError::Timeout);
    CHECK_EQ(s.last_failed_rssi, -92);
    CHECK_EQ(s.rx_timeout, uint32_t {1});
}

// Sx1262::send() begins with SetStandby, which tears down a reception already
// in progress — so transmitting over one loses the packet we were half way
// through receiving, on top of corrupting it for whoever sent it.
static void test_transmission_waits_for_a_clear_channel() {
    ManualClock clock;
    EventLoop loop(clock);
    GatedRadio radio;
    radio.set_ready(true);
    radio.set_channel_busy(true);
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet packet;
    packet.type = proto::PayloadType::Ack;
    packet.payload = {1, 2, 3, 4};
    CHECK(dispatcher.send(std::move(packet), kPriorityDirect));

    // Nothing goes out over the top of a reception, however long we wait.
    loop.advance(1000);
    CHECK_EQ(radio.send_count(), size_t {0});
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});
    CHECK(dispatcher.stats().tx_deferred > 0);

    // And it leaves as soon as the air is clear again.
    radio.set_channel_busy(false);
    loop.advance(200);
    CHECK_EQ(radio.send_count(), size_t {1});
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});
    CHECK_EQ(dispatcher.stats().tx_forced, uint32_t {0});
}

// Politeness cannot be unbounded: a band that never goes quiet, or a receiver
// stuck believing it hears a preamble, would otherwise stall every queue on the
// node for good.
static void test_a_channel_that_never_clears_does_not_stall_the_queue() {
    ManualClock clock;
    EventLoop loop(clock);
    GatedRadio radio;
    radio.set_ready(true);
    radio.set_channel_busy(true);
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet packet;
    packet.type = proto::PayloadType::Ack;
    // Long enough not to expire while the dispatcher is being polite.
    packet.payload = {1, 2, 3, 4};
    CHECK(dispatcher.send(std::move(packet), kPriorityFlood));

    loop.advance(3000);
    CHECK_EQ(radio.send_count(), size_t {0});

    // Past the ceiling it goes out anyway, and says so.
    loop.advance(2000);
    CHECK_EQ(radio.send_count(), size_t {1});
    CHECK_EQ(dispatcher.stats().tx_forced, uint32_t {1});
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
    ManualClock clock;
    EventLoop loop(clock);
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

    // The jitter is at most 400 ms, so on virtual time this is exact: if the
    // stale one-second recheck were still what woke us, nothing would have
    // gone out yet.
    loop.advance(401);
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
    GatedRadio radio;
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
    ManualClock clock;
    EventLoop loop(clock);
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

    // A send that never made it onto the air advances on the next loop pass
    // rather than waiting out the ladder.
    loop.advance(5);

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

static void test_retry_ladder_runs_out_of_attempts() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    contacts.set_path(peer, Bytes {0xAA, 0xBB});

    ManualClock clock;
    EventLoop loop(clock);
    GatedRadio radio;
    radio.set_ready(true);
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    ReliableSender sender(loop, dispatcher, *self, contacts);
    CHECK(sender.send(peer, "are you there?", proto::kTxtPlain, pv::kFixedTime).has_value());
    CHECK_EQ(radio.send_count(), size_t {1});
    radio.complete_tx();

    auto first = proto::Packet::decode(radio.last_sent());
    CHECK(first.has_value());
    if (first) CHECK(first->is_direct());

    // 8 s, then 16 s, then 32 s — and nothing goes out a millisecond early.
    size_t attempts = 1;
    for (uint32_t delay : {8000u, 16000u, 32000u}) {
        loop.advance(delay - 1);
        CHECK_EQ(radio.send_count(), attempts);
        loop.advance(1);
        CHECK_EQ(radio.send_count(), ++attempts);
        radio.complete_tx();
    }
    CHECK_EQ(radio.send_count(), size_t {4});

    // The last attempt escalates to flood: a stale direct path is the usual
    // reason an ack never arrived.
    auto last = proto::Packet::decode(radio.last_sent());
    CHECK(last.has_value());
    if (last) CHECK(last->is_flood());

    // Four is all the attempt counter can express on the wire, so the send is
    // abandoned rather than retried a fifth time.
    CHECK_EQ(sender.pending(), size_t {1});
    loop.advance(32000);
    CHECK_EQ(radio.send_count(), size_t {4});
    CHECK_EQ(sender.pending(), size_t {0});
}

static void test_queued_packet_expiry_reports_failure() {
    ManualClock clock;
    EventLoop loop(clock);
    GatedRadio radio;  // never becomes ready
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));

    proto::Packet advert;
    advert.type = proto::PayloadType::Advert;
    advert.payload = {1, 2, 3, 4};

    bool reported = false;
    bool transmitted = true;
    CHECK(dispatcher.send(advert, kPriorityAdvert, 0, [&](bool sent) {
        reported = true;
        transmitted = sent;
    }));

    // Queued packets expire after ten seconds per priority level, so a minute
    // for an advert. The radio never comes up; the recheck keeps looking.
    loop.advance(59000);
    CHECK(!reported);
    CHECK_EQ(dispatcher.queue_depth(), size_t {1});

    loop.advance(2000);
    CHECK(reported);
    CHECK(!transmitted);
    CHECK_EQ(dispatcher.queue_depth(), size_t {0});
    CHECK_EQ(dispatcher.stats().tx_dropped, uint32_t {1});
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

    const std::string path = "/tmp/coreletd_test_contacts_touch";
    ContactStore contacts(*self, path);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubA));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));
    radio.set_ready(true);

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    // Nothing about the route changes on receipt — routes come only from
    // returned paths — so last_seen is the only reason the store can come out
    // dirty.
    CHECK(contacts.save());
    CHECK(!contacts.dirty());
    std::remove(path.c_str());

    radio.inject(from_hex(pv::kTextPacket));

    CHECK(node.has_messages());
    CHECK(peer.last_seen != 0);
    CHECK(peer.last_rssi != 0);
    CHECK(contacts.dirty());
}

// The attempt number is two bits of the flags byte, so every retry is a
// different packet and packet-level dedup cannot see that they are the same
// message. A sender that never hears our ack works through its whole ladder,
// and the app used to be shown the same text once per attempt.
static void test_retries_are_acked_every_time_but_delivered_once() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    auto peer_id = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self || !peer_id) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubA));
    contacts.set_path(peer, {});
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));
    radio.set_ready(true);

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    const Bytes shared = peer.shared_secret(*peer_id);
    CHECK(!shared.empty());

    // The same message, sent four times, as a sender that hears no ack does.
    for (uint8_t attempt = 0; attempt < 4; attempt++) {
        proto::TextMessage msg;
        msg.timestamp = 1700000000;
        msg.txt_type = proto::kTxtPlain;
        msg.attempt = attempt;
        msg.text = from_str("are you there");

        auto env = proto::DirectEnvelope::seal(self->pub()[0], peer_id->pub()[0], shared,
                                               msg.encode());
        proto::Packet p;
        p.type = proto::PayloadType::TxtMsg;
        p.route = proto::RouteType::Flood;
        p.payload = env.encode();
        radio.inject(p.encode());
        // The test radio holds a transmission in flight until it is completed,
        // so let each ack finish before the next attempt arrives.
        radio.complete_tx();
    }

    // Every attempt is acked: the sender is retrying precisely because it did
    // not hear the last one, so staying silent would guarantee another retry.
    CHECK_EQ(radio.send_count(), size_t {4});

    // But the app is shown it once.
    CHECK(node.has_messages());
    auto first = node.pop_message();
    CHECK(first.has_value());
    if (first) CHECK(first->text == "are you there");
    CHECK(!node.has_messages());

    // A genuinely different message from the same peer still gets through.
    proto::TextMessage other;
    other.timestamp = 1700000001;
    other.txt_type = proto::kTxtPlain;
    other.text = from_str("are you there");
    auto env = proto::DirectEnvelope::seal(self->pub()[0], peer_id->pub()[0], shared,
                                           other.encode());
    proto::Packet p;
    p.type = proto::PayloadType::TxtMsg;
    p.route = proto::RouteType::Flood;
    p.payload = env.encode();
    radio.inject(p.encode());
    CHECK(node.has_messages());
}

static void test_direct_ack_marks_store_dirty() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string path = "/tmp/coreletd_test_contacts_ack";
    ContactStore contacts(*self, path);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubB));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));
    radio.set_ready(true);

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
// A peer that floods to us has no route back, and it only ever learns one from
// a returned path: MeshCore does not take routes from adverts. Without this the
// peer floods every packet to us for good, doubling the airtime in that
// direction permanently.
static void test_flood_message_is_answered_with_a_path_return() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    auto peer_id = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self || !peer_id) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubA));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));
    radio.set_ready(true);

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    const Bytes shared = peer.shared_secret(*peer_id);
    CHECK(!shared.empty());
    if (shared.empty()) return;

    // Two hops of flood path, so the route in the reply is something other
    // than empty and its direction is observable.
    auto send_text = [&](proto::RouteType route, uint32_t timestamp) {
        proto::TextMessage msg;
        msg.timestamp = timestamp;
        msg.txt_type = proto::kTxtPlain;
        msg.text = from_str("are you there");
        proto::Packet p;
        p.type = proto::PayloadType::TxtMsg;
        p.route = route;
        p.path_hash_size = 1;
        if (route == proto::RouteType::Flood) p.path = {0x11, 0x22};
        p.payload = proto::DirectEnvelope::seal(self->pub()[0], peer_id->pub()[0], shared,
                                                msg.encode())
                        .encode();
        radio.inject(p.encode());
        radio.complete_tx();
    };

    send_text(proto::RouteType::Flood, 1700000000);

    CHECK_EQ(radio.send_count(), size_t {1});
    auto sent = proto::Packet::decode(radio.last_sent());
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Path);

    // Flooded, as MeshCore floods it: we hold no route to the sender, and the
    // path its packet took, reversed, is a guess about links nobody has used.
    // It is not installed as a route either.
    CHECK(sent->is_flood());
    CHECK(sent->path.empty());
    CHECK(!peer.path_known);

    auto env = proto::DirectEnvelope::decode(sent->payload);
    CHECK(env.has_value());
    if (!env) return;
    auto plain = crypto::mac_and_decrypt(shared, env->mac, env->ciphertext);
    CHECK(plain.has_value());
    if (!plain) return;
    auto ret = proto::PathReturn::decode(*plain);
    CHECK(ret.has_value());
    if (!ret) return;

    // Unreversed: this is the order the peer's packets will travel in, which
    // is the opposite of the order ours do.
    CHECK_BYTES(ret->path, (Bytes {0x11, 0x22}));
    CHECK_EQ(ret->path_hash_size, uint8_t {1});

    // And the ack rides inside it rather than costing a second transmission.
    CHECK(ret->has_extra);
    CHECK_EQ(ret->extra_type, static_cast<uint8_t>(proto::PayloadType::Ack));
    CHECK(ret->extra.size() >= crypto::kAckHashSize);

    // A direct-routed message needs no such thing: the sender demonstrably has
    // a route already, so the reply is a plain ack.
    send_text(proto::RouteType::Direct, 1700000001);
    CHECK_EQ(radio.send_count(), size_t {2});
    auto ack = proto::Packet::decode(radio.last_sent());
    CHECK(ack.has_value());
    if (ack) {
        CHECK(ack->type == proto::PayloadType::Ack);
        CHECK_EQ(ack->payload.size(), size_t {6});
    }
}

// A peer whose own PATH reaches us flood-routed has no route to us either, so
// it gets one back — direct, along the route it just gave us. Its reply lands
// direct-routed, which is what stops the exchange rather than bouncing.
static void test_flood_path_return_is_reciprocated() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    auto peer_id = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self || !peer_id) return;

    ContactStore contacts(*self);
    Contact& peer = *contacts.upsert(from_hex(pv::kPubA));
    ChannelStore channels;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher(loop, radio);
    std::string error;
    CHECK(dispatcher.start(error));
    radio.set_ready(true);

    Node node(loop, dispatcher, *self, contacts, channels, Node::Config {});
    node.start();

    const Bytes shared = peer.shared_secret(*peer_id);
    if (shared.empty()) return;

    auto send_path = [&](proto::RouteType route) {
        proto::PathReturn ret;
        ret.path = {0x33};  // the route the peer says to use for it
        proto::Packet p;
        p.type = proto::PayloadType::Path;
        p.route = route;
        p.path_hash_size = 1;
        if (route == proto::RouteType::Flood) p.path = {0x44};
        p.payload = proto::DirectEnvelope::seal(self->pub()[0], peer_id->pub()[0], shared,
                                                ret.encode())
                        .encode();
        radio.inject(p.encode());
        radio.complete_tx();
    };

    send_path(proto::RouteType::Flood);

    // The route it gave us is stored, and the reply goes back along it.
    CHECK(peer.path_known);
    CHECK_BYTES(peer.out_path, (Bytes {0x33}));
    CHECK_EQ(radio.send_count(), size_t {1});
    auto sent = proto::Packet::decode(radio.last_sent());
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Path);
    CHECK(sent->is_direct());
    CHECK_BYTES(sent->path, (Bytes {0x33}));

    auto env = proto::DirectEnvelope::decode(sent->payload);
    if (!env) return;
    auto plain = crypto::mac_and_decrypt(shared, env->mac, env->ciphertext);
    CHECK(plain.has_value());
    if (!plain) return;
    auto ret = proto::PathReturn::decode(*plain);
    CHECK(ret.has_value());
    if (ret) {
        // The inbound path, unreversed, is the peer's route to us.
        CHECK_BYTES(ret->path, (Bytes {0x44}));
        // Nothing to bundle, so MeshCore's dummy type and four random bytes go
        // in instead: two identical path returns would otherwise be one packet
        // as far as every repeater between here and there is concerned.
        CHECK(ret->has_extra);
        CHECK_EQ(ret->extra_type, uint8_t {0x0F});
    }

    // A direct-routed one needs no answer: the sender has a route already, and
    // replying to every reply is how two nodes talk to each other for ever.
    send_path(proto::RouteType::Direct);
    CHECK_EQ(radio.send_count(), size_t {1});
}

// ---------------------------------------------------------------------------
// MeshCore's receive rules, one by one, against Mesh::onRecvPacket and
// BaseChatMesh. One node on virtual time, with A on the far side of the air.
// ---------------------------------------------------------------------------

namespace {

struct AckSpy : Node::Delegate {
    int acks = 0;
    void on_ack(ByteView) override { acks++; }
};

struct Bench {
    std::optional<crypto::LocalIdentity> self;  // B, the node under test
    std::optional<crypto::LocalIdentity> peer;  // A, on the far side
    ContactStore contacts;
    ChannelStore channels;
    ManualClock clock;
    EventLoop loop;
    GatedRadio radio;
    Dispatcher dispatcher;
    Node node;
    AckSpy spy;
    Contact* a = nullptr;
    Bytes shared;

    explicit Bench(Node::Config cfg = {})
        : self(crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB))),
          peer(crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA))),
          contacts(*self),
          loop(clock),
          dispatcher(loop, radio),
          node(loop, dispatcher, *self, contacts, channels, std::move(cfg)) {
        a = contacts.upsert(from_hex(pv::kPubA));
        std::string error;
        dispatcher.start(error);
        radio.set_ready(true);
        node.set_delegate(&spy);
        node.start();
        shared = a->shared_secret(*self);
    }

    uint8_t us() const { return self->pub()[0]; }

    // A text from A to us, sealed as A would seal it.
    Bytes text_from_a(uint8_t txt_type, uint32_t timestamp, Bytes text) {
        proto::TextMessage msg;
        msg.timestamp = timestamp;
        msg.txt_type = txt_type;
        msg.text = std::move(text);
        return proto::DirectEnvelope::seal(us(), peer->pub()[0], shared, msg.encode()).encode();
    }

    void inject(proto::PayloadType type, proto::RouteType route, Bytes path, Bytes payload,
                uint8_t hash_size = 1) {
        proto::Packet p;
        p.type = type;
        p.route = route;
        p.path = std::move(path);
        p.path_hash_size = hash_size;
        p.payload = std::move(payload);
        radio.inject(p.encode());
    }

    std::optional<proto::Packet> last_sent() { return proto::Packet::decode(radio.last_sent()); }

    // Lets a relay's stagger and any transmission already on the air run out,
    // so that send_count() afterwards is everything a packet caused.
    void settle() {
        for (int i = 0; i < 4; i++) {
            loop.advance(1200);
            radio.complete_tx();
        }
    }

    std::optional<proto::PathReturn> open_path_return(const proto::Packet& p) {
        auto env = proto::DirectEnvelope::decode(p.payload);
        if (!env) return std::nullopt;
        auto plain = crypto::mac_and_decrypt(shared, env->mac, env->ciphertext);
        if (!plain) return std::nullopt;
        return proto::PathReturn::decode(*plain);
    }
};

}  // namespace

// Routes come only from returned paths. A flood advert's path reversed is a
// guess about links nobody has used, and MeshCore does not take it; nor a
// flood message's. A wrong guess would sit over the route the peer told us.
static void test_flood_paths_are_not_turned_into_routes() {
    Bench b;
    b.contacts.set_path(*b.a, Bytes {0x33});  // what the peer told us

    auto advert = proto::Packet::decode(from_hex(pv::kAdvertPacket));
    CHECK(advert.has_value());
    if (!advert) return;
    b.inject(proto::PayloadType::Advert, proto::RouteType::Flood, {0x11, 0x22}, advert->payload);
    CHECK_EQ(b.a->adv_timestamp, pv::kFixedTime);
    CHECK_BYTES(b.a->out_path, (Bytes {0x33}));

    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Flood, {0x11, 0x22},
             b.text_from_a(proto::kTxtPlain, 1700000000, from_str("hello")));
    CHECK(b.node.has_messages());
    CHECK(b.a->path_known);
    CHECK_BYTES(b.a->out_path, (Bytes {0x33}));
}

// A flood-routed ack from a contact we hold a route for means it holds none for
// us: our path return never reached it, or has not yet. MeshCore offers the
// route again, direct, three seconds later (handleReturnPathRetry); a peer that
// never hears one floods at us for good.
static void test_flood_ack_from_a_routed_contact_is_offered_the_route_again() {
    Bench b;
    b.contacts.set_path(*b.a, Bytes {0x33});

    auto ack = b.node.send_text(*b.a, "hello", proto::kTxtPlain, pv::kFixedTime);
    CHECK(ack.has_value());
    if (!ack) return;
    CHECK_EQ(b.radio.send_count(), size_t {1});
    b.radio.complete_tx();

    // A heard it, but has no route to us, so its ack comes back flooded.
    Bytes payload = *ack;
    payload.push_back(0x00);
    payload.push_back(0x5A);
    b.inject(proto::PayloadType::Ack, proto::RouteType::Flood, {0x44}, payload);
    CHECK_EQ(b.spy.acks, 1);

    // Nothing for three seconds, then the route, direct along the one we hold.
    b.loop.advance(2999);
    CHECK_EQ(b.radio.send_count(), size_t {1});
    b.loop.advance(1);
    CHECK_EQ(b.radio.send_count(), size_t {2});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Path);
    CHECK(sent->is_direct());
    CHECK_BYTES(sent->path, (Bytes {0x33}));
    auto ret = b.open_path_return(*sent);
    CHECK(ret.has_value());
    // The ack's inbound path, unreversed, is the peer's route to us.
    if (ret) CHECK_BYTES(ret->path, (Bytes {0x44}));
    b.radio.complete_tx();

    // A direct-routed ack says the peer has a route: nothing to remind it of.
    ack = b.node.send_text(*b.a, "hello again", proto::kTxtPlain, pv::kFixedTime + 1);
    CHECK(ack.has_value());
    if (!ack) return;
    CHECK_EQ(b.radio.send_count(), size_t {3});
    b.radio.complete_tx();
    payload = *ack;
    payload.push_back(0x00);
    payload.push_back(0x5B);
    b.inject(proto::PayloadType::Ack, proto::RouteType::Direct, {}, payload);
    CHECK_EQ(b.spy.acks, 2);
    b.loop.advance(3000);
    CHECK_EQ(b.radio.send_count(), size_t {3});
}

// A direct-routed packet with hops left on its path is in transit, not for us.
// MeshCore does not decrypt one; what it does read out of one is an ack, early.
static void test_in_transit_direct_packets_are_not_opened() {
    Bench b;

    // Addressed to us, but the path says it has a hop to go. Opening it would
    // ack a message the sender is still expecting to travel.
    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {0x55},
             b.text_from_a(proto::kTxtPlain, 1700000000, from_str("not yet")));
    CHECK(!b.node.has_messages());
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {0});  // no ack, and nothing relayed

    // With its path consumed, the same kind of text is ours.
    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {},
             b.text_from_a(proto::kTxtPlain, 1700000001, from_str("now")));
    CHECK(b.node.has_messages());
    CHECK_EQ(b.radio.send_count(), size_t {1});
    b.radio.complete_tx();

    // An ack passing through is read on the way past.
    b.contacts.set_path(*b.a, Bytes {0x33});
    auto ack = b.node.send_text(*b.a, "hello", proto::kTxtPlain, pv::kFixedTime);
    CHECK(ack.has_value());
    if (!ack) return;
    b.radio.complete_tx();
    Bytes payload = *ack;
    payload.push_back(0x00);
    payload.push_back(0x5A);
    b.inject(proto::PayloadType::Ack, proto::RouteType::Direct, {0x55}, payload);
    CHECK_EQ(b.spy.acks, 1);
}

// With relaying on, a direct-routed packet whose next hop is us goes on down
// the rest of its path with our hop consumed — the half of relaying that
// repeating floods makes necessary, since peers build routes through a node
// they saw in a flood path.
static void test_relay_forwards_direct_packets_through_us() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);
    const uint8_t us = b.us();

    const Bytes through = b.text_from_a(proto::kTxtPlain, 1700000000, from_str("through"));
    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {us, 0x66}, through);
    CHECK(!b.node.has_messages());
    // Spread over up to one packet's airtime, as MeshCore's companion does.
    b.loop.advance(1000);
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (sent) {
        CHECK(sent->is_direct());
        CHECK_BYTES(sent->path, (Bytes {0x66}));
        CHECK_BYTES(sent->payload, through);
    }
    b.radio.complete_tx();

    // Somebody else's hop is not ours to send.
    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {0x77, us},
             b.text_from_a(proto::kTxtPlain, 1700000001, from_str("elsewhere")));
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {1});

    // An ack passing through that answers our own send is consumed, not
    // forwarded: MeshCore marks it do-not-retransmit.
    b.contacts.set_path(*b.a, Bytes {0x33});
    auto ack = b.node.send_text(*b.a, "hello", proto::kTxtPlain, pv::kFixedTime);
    CHECK(ack.has_value());
    if (!ack) return;
    CHECK_EQ(b.radio.send_count(), size_t {2});
    b.radio.complete_tx();
    Bytes payload = *ack;
    payload.push_back(0x00);
    payload.push_back(0x5A);
    b.inject(proto::PayloadType::Ack, proto::RouteType::Direct, {us, 0x66}, payload);
    CHECK_EQ(b.spy.acks, 1);
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {2});

    // One for somebody else goes on, straight away.
    b.inject(proto::PayloadType::Ack, proto::RouteType::Direct, {us, 0x66}, {9, 8, 7, 6, 5, 4});
    CHECK_EQ(b.radio.send_count(), size_t {3});
    sent = b.last_sent();
    CHECK(sent.has_value());
    if (sent) {
        CHECK(sent->type == proto::PayloadType::Ack);
        CHECK_BYTES(sent->path, (Bytes {0x66}));
    }
}

// The hop a relay appends is as wide as the packet's hashes
// (Mesh::routeRecvPacket copies getPathHashSize() bytes of the key). A one-byte
// hop could not be pushed onto a two-byte path, and the packet was silently
// never repeated.
// tag(4) auth(4) flags(1), then the route; the low two flag bits size its hashes.
static Bytes trace_payload(uint8_t flags, ByteView route) {
    Bytes p {0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, flags};
    p.insert(p.end(), route.begin(), route.end());
    return p;
}

// A trace is routed by its payload, not its path: the path is the SNR each hop
// heard it at. With repeat on, MeshCore sends one on when the next hash in its
// route is ours, appending what it heard it at.
static void test_relay_forwards_a_trace_routed_through_us() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);
    const uint8_t us = b.us();

    const Bytes route = trace_payload(0, Bytes {0x66, us, 0x66});
    proto::Packet p;
    p.type = proto::PayloadType::Trace;
    p.route = proto::RouteType::Direct;
    p.path = {0x28};  // the first hop's reading
    p.payload = route;
    b.radio.inject(p.encode(), -90, -7.75f);
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (sent) {
        CHECK(sent->type == proto::PayloadType::Trace);
        CHECK(sent->is_direct());
        CHECK_BYTES(sent->path, (Bytes {0x28, 0xE1}));  // -7.75 dB is -31 quarters
        CHECK_BYTES(sent->payload, route);
    }

    // Hashes as wide as the flags say: two bytes of our key here.
    const Bytes wide = trace_payload(1, Bytes {b.self->pub()[0], b.self->pub()[1]});
    b.inject(proto::PayloadType::Trace, proto::RouteType::Direct, {}, wide);
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {2});
    sent = b.last_sent();
    if (sent) CHECK_BYTES(sent->path, (Bytes {0x18}));  // the bench's 6 dB

    // Somebody else's turn, and a trace that has reached the end of its route.
    b.inject(proto::PayloadType::Trace, proto::RouteType::Direct, {},
             trace_payload(0, Bytes {0x66, us}));
    b.inject(proto::PayloadType::Trace, proto::RouteType::Direct, {0x10, 0x20},
             trace_payload(0, Bytes {0x66, us}));
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {2});
}

// The case that reading a trace's path as a route gets wrong: a reading equal to
// our hash looks exactly like us being the next hop.
static void test_trace_readings_are_not_mistaken_for_hops() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);
    const uint8_t us = b.us();
    b.inject(proto::PayloadType::Trace, proto::RouteType::Direct, {us},
             trace_payload(0, Bytes {0x66, 0x77}));
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {0});
}

static void test_trace_is_not_forwarded_without_repeat() {
    Bench b;
    b.inject(proto::PayloadType::Trace, proto::RouteType::Direct, {},
             trace_payload(0, Bytes {b.us()}));
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {0});
}

// MeshCore delivers a control packet with its top bit set only at zero hops and
// never forwards one; without that bit it is direct traffic like any other.
static void test_zero_hop_control_is_never_forwarded() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);
    const uint8_t us = b.us();
    b.inject(proto::PayloadType::Control, proto::RouteType::Direct, {us, 0x66}, {0x80, 1, 2, 3});
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {0});

    b.inject(proto::PayloadType::Control, proto::RouteType::Direct, {us, 0x66}, {0x10, 1, 2, 3});
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    if (sent) CHECK_BYTES(sent->path, (Bytes {0x66}));
}

// MeshCore opens a REQ, RESPONSE or ANON_REQ addressed to it before deciding
// whether to flood it on, and one that opens was for this node and goes no
// further — even though a companion node answers none of them.
static void test_relay_does_not_repeat_requests_that_open_for_us() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);
    const uint8_t us = b.us();
    const uint8_t them = b.peer->pub()[0];

    auto sends_for = [&](proto::PayloadType type, Bytes payload) {
        const size_t before = b.radio.send_count();
        b.inject(type, proto::RouteType::Flood, {0x11}, std::move(payload));
        b.settle();
        return b.radio.send_count() - before;
    };
    const Bytes request {0x10, 0x20, 0x30, 0x40, 0x01};  // timestamp, request type

    for (auto type : {proto::PayloadType::Req, proto::PayloadType::Response}) {
        Bytes sealed = proto::DirectEnvelope::seal(us, them, b.shared, request).encode();
        CHECK_EQ(sends_for(type, sealed), size_t {0});

        // Our first key byte, but no contact's key opens it: somebody else's.
        Bytes stranger = proto::DirectEnvelope::seal(us, them, Bytes(32, 0x5A), request).encode();
        CHECK_EQ(sends_for(type, stranger), size_t {1});

        Bytes elsewhere = proto::DirectEnvelope::seal(static_cast<uint8_t>(us ^ 0xFF), them,
                                                      b.shared, request).encode();
        CHECK_EQ(sends_for(type, elsewhere), size_t {1});
    }

    // An anonymous request carries its sender's key, so it opens for us from
    // somebody who is not a contact at all.
    auto anon_shared = b.peer->shared_secret(b.self->pub());
    CHECK(anon_shared.has_value());
    if (!anon_shared) return;
    const Bytes a_key = b.a->pubkey;
    b.contacts.remove(a_key);
    Bytes anon = proto::AnonReqEnvelope::seal(us, b.peer->pub(), *anon_shared, request).encode();
    CHECK_EQ(sends_for(proto::PayloadType::AnonReq, anon), size_t {0});

    Bytes tampered = anon;
    tampered.back() ^= 0x01;
    CHECK_EQ(sends_for(proto::PayloadType::AnonReq, tampered), size_t {1});
}

static void test_relay_repeats_with_the_packets_hash_size() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);

    // A group text on a channel we do not hold: nothing to decrypt, and
    // MeshCore floods it on regardless.
    proto::TextMessage msg;
    msg.timestamp = 1700000000;
    msg.text = from_str("someone: hi");
    const Bytes key(16, 0x42);
    const Bytes payload = proto::GroupEnvelope::seal(0xAB, key, msg.encode()).encode();
    b.inject(proto::PayloadType::GrpTxt, proto::RouteType::Flood, {0x11, 0x22, 0x33, 0x44},
             payload, /*hash_size=*/2);
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->is_flood());
    CHECK_EQ(sent->path_hash_size, uint8_t {2});
    CHECK_BYTES(sent->path,
                (Bytes {0x11, 0x22, 0x33, 0x44, b.self->pub()[0], b.self->pub()[1]}));
    CHECK_BYTES(sent->payload, payload);
}

// The flood side of relaying repeats only what Mesh::routeRecvPacket would.
static void test_relay_repeats_only_what_meshcore_floods_on() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);

    // Sends caused by one injected packet, once everything has settled.
    auto sends_for = [&](proto::PayloadType type, Bytes payload) {
        const size_t before = b.radio.send_count();
        b.inject(type, proto::RouteType::Flood, {0x11}, std::move(payload));
        b.settle();
        return b.radio.send_count() - before;
    };
    auto last_type = [&] {
        auto p = b.last_sent();
        return p ? p->type : proto::PayloadType::RawCustom;
    };

    // An advert is repeated once its signature verifies, and never before:
    // every MeshCore node drops a forgery, so a relay that passed one along
    // would be the one thing on the mesh amplifying it.
    auto advert = proto::Packet::decode(from_hex(pv::kAdvertPacket));
    CHECK(advert.has_value());
    if (!advert) return;
    Bytes forged = advert->payload;
    forged.back() ^= 0x01;  // the last byte of the name
    CHECK_EQ(sends_for(proto::PayloadType::Advert, forged), size_t {0});
    CHECK_EQ(sends_for(proto::PayloadType::Advert, advert->payload), size_t {1});
    CHECK(last_type() == proto::PayloadType::Advert);

    // Types MeshCore never flood-routes.
    const Bytes nine(9, 0x01);
    CHECK_EQ(sends_for(proto::PayloadType::Trace, nine), size_t {0});
    CHECK_EQ(sends_for(proto::PayloadType::Control, nine), size_t {0});
    CHECK_EQ(sends_for(proto::PayloadType::RawCustom, nine), size_t {0});
    CHECK_EQ(sends_for(proto::PayloadType::Multipart, nine), size_t {0});

    // A text we decrypted was for us: it is answered, not repeated.
    CHECK_EQ(sends_for(proto::PayloadType::TxtMsg,
                       b.text_from_a(proto::kTxtPlain, 1700000000, from_str("for us"))),
             size_t {1});
    CHECK(last_type() == proto::PayloadType::Path);

    // One for somebody else — a different first key byte — goes on.
    Bytes elsewhere = b.text_from_a(proto::kTxtPlain, 1700000001, from_str("for them"));
    elsewhere[0] = static_cast<uint8_t>(b.us() ^ 0xFF);
    CHECK_EQ(sends_for(proto::PayloadType::TxtMsg, elsewhere), size_t {1});
    CHECK(last_type() == proto::PayloadType::TxtMsg);

    // An ack that answered our own send is consumed; any other is repeated.
    auto ack = b.node.send_text(*b.a, "hello", proto::kTxtPlain, pv::kFixedTime);
    CHECK(ack.has_value());
    if (!ack) return;
    b.settle();
    Bytes ours = *ack;
    ours.push_back(0x00);
    ours.push_back(0x5A);
    CHECK_EQ(sends_for(proto::PayloadType::Ack, ours), size_t {0});
    CHECK_EQ(b.spy.acks, 1);
    CHECK_EQ(sends_for(proto::PayloadType::Ack, {9, 8, 7, 6, 5, 4}), size_t {1});

    // Group text goes on whether or not we could read it.
    proto::TextMessage msg;
    msg.timestamp = 1700000002;
    msg.text = from_str("someone: hi");
    const Bytes key(16, 0x42);
    CHECK_EQ(sends_for(proto::PayloadType::GrpTxt,
                       proto::GroupEnvelope::seal(0xAB, key, msg.encode()).encode()),
             size_t {1});
}

// MeshCore ignores an advert with no name (BaseChatMesh::onAdvertRecv), so a
// contact made from one would be a contact no other node on the mesh holds.
// The packet is still repeated: its signature was good.
static void test_nameless_advert_is_ignored_but_still_repeated() {
    Node::Config cfg;
    cfg.repeat = true;
    Bench b(cfg);

    proto::AdvertAppData app;
    app.flags = proto::kAdvTypeChat;  // no name bit, no name
    proto::Advert adv = proto::Advert::create(*b.peer, pv::kFixedTime, app);
    b.inject(proto::PayloadType::Advert, proto::RouteType::Flood, {}, adv.encode());
    CHECK_EQ(b.a->adv_timestamp, uint32_t {0});
    CHECK(b.a->name.empty());
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {1});

    // The name bit set over nothing is the same thing to MeshCore: hasName()
    // looks at the first byte of the name, not at the flag.
    app.flags = proto::kAdvTypeChat | proto::kAdvHasName;
    adv = proto::Advert::create(*b.peer, pv::kFixedTime + 1, app);
    b.inject(proto::PayloadType::Advert, proto::RouteType::Flood, {}, adv.encode());
    CHECK_EQ(b.a->adv_timestamp, uint32_t {0});

    // With a name, as every real advert has, it lands.
    app.name = "A";
    adv = proto::Advert::create(*b.peer, pv::kFixedTime + 2, app);
    b.inject(proto::PayloadType::Advert, proto::RouteType::Flood, {}, adv.encode());
    CHECK_EQ(b.a->adv_timestamp, pv::kFixedTime + 2);
    CHECK(b.a->name == "A");
}

// MeshCore drops a text of a type it does not know, without an ack, and a group
// text whose type bits are set likewise. Delivering them would hand the app
// bytes with a meaning nobody has defined; acking them would commit to a hash
// rule the new type may not share.
static void test_unknown_text_types_are_dropped_unacked() {
    Bench b;

    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {},
             b.text_from_a(5, 1700000000, from_str("future")));
    CHECK(!b.node.has_messages());
    b.settle();
    CHECK_EQ(b.radio.send_count(), size_t {0});

    auto group = [&](uint8_t txt_type) {
        proto::TextMessage msg;
        msg.timestamp = 1700000000 + txt_type;
        msg.txt_type = txt_type;
        msg.text = from_str("someone: hi");
        const Channel pub = Channel::public_channel();
        return proto::GroupEnvelope::seal(pub.hash(), pub.secret, msg.encode()).encode();
    };
    b.inject(proto::PayloadType::GrpTxt, proto::RouteType::Flood, {}, group(1));
    CHECK(!b.node.has_messages());
    b.inject(proto::PayloadType::GrpTxt, proto::RouteType::Flood, {}, group(0));
    CHECK(b.node.has_messages());
}

// A signed message carries the sender's key prefix between the header and the
// text. The prefix is raw key bytes, so a zero in it is not a terminator:
// MeshCore reads the text from byte 9 and hashes 9 + strlen(&data[9]) with the
// recipient's key. Scanning from byte 5 found one byte of "text" and an ack
// that never matched, for one room server in sixty-odd.
static void test_signed_text_is_read_and_acked_from_byte_nine() {
    Bench b;

    Bytes text {0xAA, 0x00, 0xBB, 0xCC};  // a prefix with a zero in it
    put_bytes(text, from_str("hi"));
    proto::TextMessage msg;
    msg.timestamp = 1700000000;
    msg.txt_type = proto::kTxtSignedPlain;
    msg.text = text;
    const Bytes plaintext = msg.encode();
    b.inject(proto::PayloadType::TxtMsg, proto::RouteType::Direct, {},
             proto::DirectEnvelope::seal(b.us(), b.peer->pub()[0], b.shared, plaintext).encode());

    auto got = b.node.pop_message();
    CHECK(got.has_value());
    if (got) {
        CHECK(got->text == "hi");
        CHECK_EQ(got->txt_type, uint8_t {proto::kTxtSignedPlain});
    }

    // The ack: SHA-256 over all eleven bytes and our own key, not over the six
    // before the zero.
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Ack);
    Bytes hashed = plaintext;  // 4 + 1 + 4 + 2 = 11 bytes, nothing to pad
    put_bytes(hashed, b.self->pub());
    CHECK_BYTES(subview(sent->payload, 0, 4), crypto::ack_hash(hashed));
}

// A returned path with wider hashes than routing can write is not stored, but
// the reciprocal path still goes back down it as given: Mesh::onRecvPacket
// sends it along the path from the packet, whatever its width.
static void test_wide_hash_path_return_is_answered_down_the_path_given() {
    Bench b;

    proto::PathReturn ret;
    ret.path = {0x33, 0x34};
    ret.path_hash_size = 2;
    b.inject(proto::PayloadType::Path, proto::RouteType::Flood, {0x44},
             proto::DirectEnvelope::seal(b.us(), b.peer->pub()[0], b.shared, ret.encode())
                 .encode());

    CHECK(!b.a->path_known);
    CHECK_EQ(b.radio.send_count(), size_t {1});
    auto sent = b.last_sent();
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Path);
    CHECK(sent->is_direct());
    CHECK_EQ(sent->path_hash_size, uint8_t {2});
    CHECK_BYTES(sent->path, (Bytes {0x33, 0x34}));
    auto back = b.open_path_return(*sent);
    CHECK(back.has_value());
    if (back) CHECK_BYTES(back->path, (Bytes {0x44}));
}

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

static void test_inbox_eviction_is_counted() {
    MessageInbox inbox(2);
    for (int i = 0; i < 5; i++) {
        StoredMessage m;
        m.text = std::to_string(i);
        inbox.store(std::move(m));
    }
    CHECK_EQ(inbox.size(), size_t {2});
    // Nothing else records that the evicted three ever arrived.
    CHECK_EQ(inbox.dropped(), uint32_t {3});
}

// An ack tells the sender to stop retrying, so a queue that does not survive a
// restart loses mail with nobody left to ask for it again.
static void test_inbox_survives_a_restart() {
    const std::string path = "/tmp/coreletd_test_inbox_restart";
    std::remove(path.c_str());

    {
        MessageInbox inbox(16, path);
        StoredMessage direct;
        direct.sender_pubkey = from_hex(pv::kPubB);
        direct.timestamp = 1700000000;
        direct.txt_type = proto::kTxtPlain;
        direct.text = "first";
        direct.snr_q4 = -20;
        direct.path_len = 0xFF;
        // store() commits on its own; nothing calls save() here on purpose.
        CHECK(inbox.store(std::move(direct)));

        StoredMessage group;
        group.is_channel = true;
        group.channel_index = 3;
        group.timestamp = 1700000001;
        group.text = "second";
        group.snr_q4 = 40;
        group.path_len = 2;
        CHECK(inbox.store(std::move(group)));
    }

    MessageInbox reloaded(16, path);
    CHECK(reloaded.load() == LoadResult::Loaded);
    CHECK_EQ(reloaded.size(), size_t {2});

    auto first = reloaded.pop();
    CHECK(first.has_value());
    if (first) {
        CHECK(!first->is_channel);
        CHECK(first->text == "first");
        CHECK_BYTES(first->sender_pubkey, from_hex(pv::kPubB));
        CHECK_EQ(first->timestamp, uint32_t {1700000000});
        CHECK_EQ(first->snr_q4, int8_t {-20});
        CHECK_EQ(first->path_len, uint8_t {0xFF});
    }

    auto second = reloaded.pop();
    CHECK(second.has_value());
    if (second) {
        CHECK(second->is_channel);
        CHECK(second->text == "second");
        CHECK_EQ(second->channel_index, uint8_t {3});
        CHECK_EQ(second->snr_q4, int8_t {40});
        CHECK_EQ(second->path_len, uint8_t {2});
    }
    std::remove(path.c_str());
}

// Message text is whatever the sender typed, and the store is one record per
// line, so a tab or a newline in a message must not be able to end the record.
static void test_inbox_text_survives_separators() {
    const std::string path = "/tmp/coreletd_test_inbox_text";
    std::remove(path.c_str());
    const std::string nasty = "line\tone\nline two\r\n# not a comment\ttrailing";

    {
        MessageInbox inbox(16, path);
        StoredMessage m;
        m.sender_pubkey = from_hex(pv::kPubB);
        m.text = nasty;
        CHECK(inbox.store(std::move(m)));
    }

    MessageInbox reloaded(16, path);
    CHECK(reloaded.load() == LoadResult::Loaded);
    CHECK_EQ(reloaded.size(), size_t {1});
    auto got = reloaded.pop();
    CHECK(got.has_value());
    if (got) CHECK(got->text == nasty);
    std::remove(path.c_str());
}

// A queue that cannot be parsed must be reported as such, not read as empty:
// an empty read would be overwritten by the next save, taking the messages
// with it.
static void test_inbox_corrupt_file_is_reported() {
    const std::string path = "/tmp/coreletd_test_inbox_corrupt";

    // Truncated mid-record, which is what an interrupted write looks like if
    // it ever reached the real file rather than the temporary one.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# coreletd messages v1\n";
        out << "direct\t" << pv::kPubB << "\t0\t1700000000\t0\t0\n";
    }
    {
        MessageInbox inbox(16, path);
        CHECK(inbox.load() == LoadResult::Corrupt);
    }

    // Present but not ours at all.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "this is not a message queue\n";
    }
    {
        MessageInbox inbox(16, path);
        CHECK(inbox.load() == LoadResult::Corrupt);
    }

    // A sender key that is not a key.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "# coreletd messages v1\n";
        out << "direct\tnothex\t0\t1700000000\t0\t0\t255\t6869\n";
    }
    {
        MessageInbox inbox(16, path);
        CHECK(inbox.load() == LoadResult::Corrupt);
    }

    std::remove(path.c_str());

    // Nothing written yet is a different answer from unreadable.
    MessageInbox fresh(16, path);
    CHECK(fresh.load() == LoadResult::Missing);
}

// A file written when the limit was higher keeps the newest, which is the end
// store() keeps when it evicts.
static void test_inbox_load_respects_a_lower_limit() {
    const std::string path = "/tmp/coreletd_test_inbox_limit";
    std::remove(path.c_str());
    {
        MessageInbox inbox(16, path);
        for (int i = 0; i < 5; i++) {
            StoredMessage m;
            m.sender_pubkey = from_hex(pv::kPubB);
            m.text = std::to_string(i);
            inbox.store(std::move(m));
        }
    }
    MessageInbox reloaded(2, path);
    CHECK(reloaded.load() == LoadResult::Loaded);
    CHECK_EQ(reloaded.size(), size_t {2});
    auto m = reloaded.pop();
    CHECK(m.has_value());
    if (m) CHECK(m->text == "3");
    std::remove(path.c_str());
}

// A queue with no path is the in-memory one the narrower tests use, and it must
// not pretend anything reached disk.
static void test_inbox_without_a_path_stays_in_memory() {
    MessageInbox inbox(4);
    StoredMessage m;
    m.text = "held";
    CHECK(inbox.store(std::move(m)));
    CHECK_EQ(inbox.size(), size_t {1});
    CHECK(inbox.load() == LoadResult::Missing);
    CHECK(!inbox.save());
}

// Companion commands are answered before their state reaches disk, so that an
// app working through its contact list one command at a time costs one durable
// replacement rather than one per contact.
// Atomic replacement makes a torn file impossible, but a bug in our own
// serialisation would still write something unreadable over the only copy. The
// save before it is kept so there is a generation to fall back to.
static void test_a_save_keeps_the_previous_version() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;
    const std::string path = "/tmp/coreletd_test_backup_contacts";
    const std::string backup = path + ".bak";
    std::remove(path.c_str());
    std::remove(backup.c_str());

    ContactStore store(*self, path);
    store.upsert(from_hex(pv::kPubB));
    CHECK(store.save());
    // Nothing to back up on a first save.
    CHECK(!std::ifstream(backup).good());

    store.upsert(from_hex(pv::kPubA));
    CHECK(store.save());
    CHECK(std::ifstream(backup).good());

    // The backup is the store as it was one save ago, not as it is now.
    ContactStore from_backup(*self, backup);
    CHECK(from_backup.load() == LoadResult::Loaded);
    CHECK_EQ(from_backup.size(), size_t {1});
    CHECK(from_backup.find(from_hex(pv::kPubB)) != nullptr);

    std::remove(path.c_str());
    std::remove(backup.c_str());
}

static void test_state_writer_batches_deferred_saves() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    if (!self) return;

    const std::string contacts_path = "/tmp/coreletd_test_writer_contacts";
    const std::string channels_path = "/tmp/coreletd_test_writer_channels";

    ManualClock clock;
    EventLoop loop(clock);
    ContactStore contacts(*self, contacts_path);
    ChannelStore channels(channels_path);
    MessageInbox inbox;
    // The production coalescing window, which only virtual time makes cheap to
    // wait out.
    StateWriter writer(loop, contacts, channels, inbox);

    contacts.upsert(from_hex(pv::kPubB));
    writer.request_save();
    channels.set(1, Channel::from_hashtag("#writer"));
    writer.request_save();

    // Neither request wrote anything on its own, nor a millisecond before the
    // window closes.
    CHECK(contacts.dirty());
    CHECK(channels.dirty());
    loop.advance(StateWriter::kCoalesceMs - 1);
    CHECK(contacts.dirty());
    CHECK(channels.dirty());

    loop.advance(1);

    // One pass covers every store that had changed, including the one whose
    // change arrived after the write was already scheduled.
    CHECK(!contacts.dirty());
    CHECK(!channels.dirty());
    CHECK(writer.healthy());

    ContactStore reloaded(*self, contacts_path);
    CHECK(reloaded.load() == LoadResult::Loaded);
    CHECK(reloaded.find(from_hex(pv::kPubB)) != nullptr);

    ChannelStore reloaded_channels(channels_path);
    CHECK(reloaded_channels.load() == LoadResult::Loaded);
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
    ContactStore contacts(*self, "/nonexistent/coreletd/contacts");
    ChannelStore channels("/nonexistent/coreletd/channels");
    MessageInbox inbox;
    StateWriter writer(loop, contacts, channels, inbox);
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
    test_duty_cycle_budget_returns_with_the_window();
    test_dispatch_result_waits_for_actual_transmission();
    test_failed_receptions_are_counted_separately();
    test_failed_receptions_carry_the_signal_they_failed_at();
    test_transmission_waits_for_a_clear_channel();
    test_a_channel_that_never_clears_does_not_stall_the_queue();
    test_identical_pending_messages_are_coalesced();
    test_earlier_pump_replaces_later_timer();
    test_dispatch_queue_drops_lowest_priority();
    test_pending_send_limit_rejects_new_message();
    test_unusable_contact_key_is_reported_as_such();
    test_retry_routes_like_the_first_send();
    test_retry_ladder_runs_out_of_attempts();
    test_queued_packet_expiry_reports_failure();
    test_contact_references_survive_insertion();
    test_received_message_marks_store_dirty();
    test_retries_are_acked_every_time_but_delivered_once();
    test_direct_ack_marks_store_dirty();
    test_flood_message_is_answered_with_a_path_return();
    test_flood_path_return_is_reciprocated();
    test_flood_paths_are_not_turned_into_routes();
    test_flood_ack_from_a_routed_contact_is_offered_the_route_again();
    test_in_transit_direct_packets_are_not_opened();
    test_relay_forwards_direct_packets_through_us();
    test_relay_forwards_a_trace_routed_through_us();
    test_trace_readings_are_not_mistaken_for_hops();
    test_trace_is_not_forwarded_without_repeat();
    test_zero_hop_control_is_never_forwarded();
    test_relay_does_not_repeat_requests_that_open_for_us();
    test_relay_repeats_with_the_packets_hash_size();
    test_relay_repeats_only_what_meshcore_floods_on();
    test_nameless_advert_is_ignored_but_still_repeated();
    test_unknown_text_types_are_dropped_unacked();
    test_signed_text_is_read_and_acked_from_byte_nine();
    test_wide_hash_path_return_is_answered_down_the_path_given();
    test_inbox_drops_oldest_when_full();
    test_inbox_eviction_is_counted();
    test_inbox_survives_a_restart();
    test_inbox_text_survives_separators();
    test_inbox_corrupt_file_is_reported();
    test_inbox_load_respects_a_lower_limit();
    test_inbox_without_a_path_stays_in_memory();
    test_a_save_keeps_the_previous_version();
    test_state_writer_batches_deferred_saves();
    test_state_writer_reports_failed_writes();
    test_contact_limit_rejects_new_but_allows_update();

    return finish("mesh");
}
