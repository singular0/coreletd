// Validates the packet/payload codec against the frozen reference vectors in
// tests/packet_vectors.h, which came from an independently written codec for the
// same wire format.

#include "crypto/crypto.h"
#include "proto/packet.h"
#include "proto/payloads.h"
#include "tests/packet_vectors.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;
using namespace clt::proto;
namespace pv = clt::pktvec;

static void test_advert_packet() {
    Bytes raw = from_hex(pv::kAdvertPacket);
    auto p = Packet::decode(raw);
    CHECK(p.has_value());
    if (!p) return;

    CHECK(p->route == RouteType::Flood);
    CHECK(p->type == PayloadType::Advert);
    CHECK_EQ(p->payload_version, uint8_t {0});
    CHECK_EQ(p->hop_count(), size_t {0});
    CHECK_BYTES(p->payload, from_hex(pv::kAdvertPayload));

    // Re-encoding must reproduce the original bytes exactly.
    CHECK_BYTES(p->encode(), raw);
}

static void test_advert_payload() {
    auto p = Packet::decode(from_hex(pv::kAdvertPacket));
    if (!p) return;

    auto adv = Advert::decode(p->payload);
    CHECK(adv.has_value());
    if (!adv) return;

    CHECK_BYTES(adv->pubkey, from_hex(pv::kPubA));
    CHECK_EQ(adv->timestamp, pv::kFixedTime);
    CHECK_BYTES(adv->appdata, from_hex(pv::kAdvertAppData));

    // The strongest check in this file: the signature only verifies if our
    // signed-region layout (pubkey || timestamp || appdata) matches MeshCore's.
    CHECK(adv->verify());

    CHECK_BYTES(adv->encode(), p->payload);
}

static void test_advert_appdata() {
    auto app = AdvertAppData::decode(from_hex(pv::kAdvertAppData));
    CHECK(app.has_value());
    if (!app) return;

    CHECK_EQ(app->node_type(), uint8_t {kAdvTypeChat});
    CHECK(app->has_location());
    CHECK(app->has_name());
    CHECK_EQ(app->lat_e6, pv::kLatE6);
    CHECK_EQ(app->lon_e6, pv::kLonE6);
    CHECK(app->name == std::string(pv::kNameA));

    CHECK_BYTES(app->encode(), from_hex(pv::kAdvertAppData));
}

static void test_advert_signature_is_rejected_when_tampered() {
    auto p = Packet::decode(from_hex(pv::kAdvertPacket));
    if (!p) return;
    auto adv = Advert::decode(p->payload);
    if (!adv) return;

    // Flipping a bit of the advertised name must invalidate the signature,
    // otherwise a repeater could rewrite node names in flight.
    CHECK(!adv->appdata.empty());
    adv->appdata.back() ^= 0x01;
    CHECK(!adv->verify());
}

static void test_advert_roundtrip_from_our_own_key() {
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    CHECK(self.has_value());
    if (!self) return;

    AdvertAppData app;
    app.flags = kAdvTypeChat | kAdvHasLocation | kAdvHasName;
    app.lat_e6 = pv::kLatE6;
    app.lon_e6 = pv::kLonE6;
    app.name = std::string(pv::kNameA);

    Advert a = Advert::create(*self, pv::kFixedTime, app);
    CHECK(a.verify());
    // Same inputs must reproduce the reference advert byte for byte.
    CHECK_BYTES(a.encode(), from_hex(pv::kAdvertPayload));
}

static void test_text_packet() {
    Bytes raw = from_hex(pv::kTextPacket);
    auto p = Packet::decode(raw);
    CHECK(p.has_value());
    if (!p) return;

    CHECK(p->type == PayloadType::TxtMsg);
    CHECK(p->route == RouteType::Flood);
    CHECK_BYTES(p->encode(), raw);

    auto env = DirectEnvelope::decode(p->payload);
    CHECK(env.has_value());
    if (!env) return;

    Bytes pub_a = from_hex(pv::kPubA);
    Bytes pub_b = from_hex(pv::kPubB);
    CHECK_EQ(env->src_hash, pub_a[0]);
    CHECK_EQ(env->dest_hash, pub_b[0]);
    CHECK_BYTES(env->encode(), p->payload);

    // Decrypt with the shared secret B would derive.
    Bytes shared = from_hex(pv::kSharedAB);
    auto plain = crypto::mac_and_decrypt(shared, env->mac, env->ciphertext);
    CHECK(plain.has_value());
    if (!plain) return;
    // Decryption yields the whole 16-byte block; the vector is the plaintext
    // before padding, so compare against the stripped form.
    CHECK_BYTES(strip_zero_padding(*plain), from_hex(pv::kTextPlaintext));

    auto msg = TextMessage::decode(*plain);
    CHECK(msg.has_value());
    if (!msg) return;
    CHECK_EQ(msg->timestamp, pv::kFixedTime);
    CHECK_EQ(msg->txt_type, uint8_t {kTxtPlain});
    CHECK_EQ(msg->attempt, uint8_t {0});
    CHECK(msg->body() == std::string(pv::kTextBody));

    // A plain-text message is acked against the *sender's* pubkey.
    CHECK_BYTES(message_ack_hash(*plain, pub_a), from_hex(pv::kTextAckHash));
}

static void test_text_encrypt_roundtrip() {
    Bytes shared = from_hex(pv::kSharedAB);
    Bytes pub_a = from_hex(pv::kPubA);
    Bytes pub_b = from_hex(pv::kPubB);

    TextMessage m;
    m.timestamp = pv::kFixedTime;
    m.txt_type = kTxtPlain;
    m.attempt = 0;
    m.text = from_str(pv::kTextBody);

    auto env = DirectEnvelope::seal(pub_b[0], pub_a[0], shared, m.encode());
    Packet p;
    p.route = RouteType::Flood;
    p.type = PayloadType::TxtMsg;
    p.payload = env.encode();

    // Must reproduce the exact reference packet built from the same inputs.
    CHECK_BYTES(p.encode(), from_hex(pv::kTextPacket));
}

static void test_ack_packet() {
    Bytes raw = from_hex(pv::kAckPacket);
    auto p = Packet::decode(raw);
    CHECK(p.has_value());
    if (!p) return;

    CHECK(p->type == PayloadType::Ack);
    CHECK(p->route == RouteType::Direct);
    CHECK_BYTES(p->payload, from_hex(pv::kTextAckHash));
    CHECK_BYTES(p->encode(), raw);
}

// The hashed region is bounded by the text's NUL terminator, which is not the
// same rule as dropping trailing zeros. These are the two cases where the
// answers differ, and an ack that hashes the wrong bytes never matches — on the
// air that is indistinguishable from a message that never arrived.
static void test_ack_region_of_an_empty_body_is_just_the_header() {
    // timestamp(4) + flags(1) + AES padding, with no text at all.
    Bytes plaintext {0x00, 0x11, 0x22, 0x33, 0x00};
    plaintext.resize(16, 0);

    // MeshCore hashes 5 bytes here. Stripping trailing zeros would eat the
    // flags byte and then the leading zero byte of the timestamp, leaving 4.
    CHECK_EQ(ack_hashed_region(plaintext).size(), size_t {5});
    CHECK_EQ(strip_zero_padding(plaintext).size(), size_t {4});
    CHECK_EQ(ack_extended_attempt(plaintext), uint8_t {0});
}

static void test_ack_region_stops_before_the_extended_attempt() {
    // timestamp(4) + flags(1) + "hi" + NUL + attempt 7, as MeshCore writes a
    // retry once the two bits in the flags byte have run out.
    Bytes plaintext {0x01, 0x02, 0x03, 0x04, 0x03};
    put_bytes(plaintext, from_str("hi"));
    plaintext.push_back(0x00);
    plaintext.push_back(0x07);

    CHECK_EQ(ack_hashed_region(plaintext).size(), size_t {7});  // 5 + strlen("hi")
    CHECK_EQ(ack_extended_attempt(plaintext), uint8_t {7});
    // Stripping trailing zeros keeps the whole thing, because the attempt byte
    // is not zero: two bytes too many, and a hash that cannot match.
    CHECK_EQ(strip_zero_padding(plaintext).size(), size_t {9});

    // And those two bytes must not reach the app as message text.
    auto msg = TextMessage::decode(plaintext);
    CHECK(msg.has_value());
    if (msg) {
        CHECK(msg->body() == "hi");
        CHECK_EQ(msg->extended_attempt, uint8_t {7});
    }
}

// Padding is not an extended attempt: the byte after the terminator is simply
// zero on an ordinary message, which is what MeshCore reads there too.
static void test_padded_message_has_no_extended_attempt() {
    Bytes plaintext {0x01, 0x02, 0x03, 0x04, 0x00};
    put_bytes(plaintext, from_str("hello"));
    plaintext.resize(16, 0);

    CHECK_EQ(ack_hashed_region(plaintext).size(), size_t {10});
    CHECK_EQ(ack_extended_attempt(plaintext), uint8_t {0});
    auto msg = TextMessage::decode(plaintext);
    CHECK(msg.has_value());
    if (msg) CHECK(msg->body() == "hello");
}

// Two acks for the same message must not be the same packet, or every repeater
// in between suppresses the second as a duplicate and a retry's ack gets one
// chance to cross the mesh.
static void test_ack_payload_is_unique_per_send() {
    const Bytes hash = from_hex(pv::kTextAckHash);
    Bytes first = ack_payload(hash, 5);
    CHECK_EQ(first.size(), size_t {6});
    CHECK_BYTES(subview(first, 0, 4), hash);
    CHECK_EQ(first[4], uint8_t {5});

    // The sixth byte is random, so a repeat is overwhelmingly likely to differ.
    bool differed = false;
    for (int i = 0; i < 32 && !differed; i++) {
        if (ack_payload(hash, 5) != first) differed = true;
    }
    CHECK(differed);
}

static void test_path_encoding() {
    // path_length packs hop count in bits 0-5 and (hash size - 1) in bits 6-7.
    Packet p;
    p.type = PayloadType::TxtMsg;
    p.route = RouteType::Direct;
    p.path_hash_size = 1;
    p.path = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    p.payload = {0x01};

    Bytes enc = p.encode();
    CHECK_EQ(enc[1], uint8_t {0x05});  // 5 hops, 1-byte hashes

    auto back = Packet::decode(enc);
    CHECK(back.has_value());
    if (back) {
        CHECK_EQ(back->hop_count(), size_t {5});
        CHECK_EQ(back->path_hash_size, uint8_t {1});
        CHECK_BYTES(back->path, p.path);
    }

    // 2-byte hashes: 5 hops -> 10 bytes, encoded as 0x45.
    Packet p2 = p;
    p2.path_hash_size = 2;
    p2.path = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Bytes enc2 = p2.encode();
    CHECK_EQ(enc2[1], uint8_t {0x45});
    auto back2 = Packet::decode(enc2);
    CHECK(back2.has_value());
    if (back2) {
        CHECK_EQ(back2->hop_count(), size_t {5});
        CHECK_EQ(back2->path_hash_size, uint8_t {2});
    }
}

static void test_path_manipulation() {
    Packet p;
    p.path_hash_size = 1;
    p.path = {0xaa, 0xbb};

    CHECK_BYTES(p.first_hop(), Bytes {0xaa});
    p.pop_hop();
    CHECK_BYTES(p.path, Bytes {0xbb});

    Bytes hop = {0xcc};
    CHECK(p.push_hop(hop));
    CHECK_BYTES(p.path, (Bytes {0xbb, 0xcc}));

    // A full path must refuse more hops rather than overflow the field.
    Packet full;
    full.path_hash_size = 1;
    full.path.assign(kMaxPathSize, 0x11);
    CHECK(!full.push_hop(hop));
}

static void test_transport_codes() {
    Packet p;
    p.route = RouteType::TransportFlood;
    p.type = PayloadType::Advert;
    p.transport_code1 = 0x1234;
    p.transport_code2 = 0xabcd;
    p.payload = {0x01, 0x02};

    Bytes enc = p.encode();
    auto back = Packet::decode(enc);
    CHECK(back.has_value());
    if (!back) return;
    CHECK(back->has_transport_codes());
    CHECK_EQ(back->transport_code1, uint16_t {0x1234});
    CHECK_EQ(back->transport_code2, uint16_t {0xabcd});
    CHECK_BYTES(back->encode(), enc);
}

static void test_malformed_packets_rejected() {
    CHECK(!Packet::decode(Bytes {}).has_value());
    // Header says transport codes follow, but the packet ends.
    CHECK(!Packet::decode(Bytes {0x10, 0x01}).has_value());
    // Header only, no path length byte.
    CHECK(!Packet::decode(Bytes {0x11}).has_value());
    // Claims 5 hops but carries no path bytes.
    CHECK(!Packet::decode(Bytes {0x11, 0x05}).has_value());
    // Reserved 4-byte path hash size.
    CHECK(!Packet::decode(Bytes {0x11, 0xC1, 1, 2, 3, 4}).has_value());
    // Path but no payload: MeshCore requires at least one byte after the path.
    CHECK(!Packet::decode(Bytes {0x11, 0x01, 0xaa}).has_value());
    CHECK(!Packet::decode(Bytes {0x11, 0x00}).has_value());

    // Payload version 2 and up are reserved for a wider envelope, so they must
    // be refused rather than mis-parsed as v1.
    CHECK(Packet::decode(Bytes {0x11, 0x00, 0x55}).has_value());
    CHECK(!Packet::decode(Bytes {0x51, 0x00, 0x55}).has_value());
    CHECK(!Packet::decode(Bytes {0x91, 0x00, 0x55}).has_value());
    CHECK(!Packet::decode(Bytes {0xD1, 0x00, 0x55}).has_value());

    // Oversized payload must be refused, matching firmware behaviour.
    Bytes big = {0x11, 0x00};
    big.insert(big.end(), kMaxPayloadSize + 1, 0x55);
    CHECK(!Packet::decode(big).has_value());
}

static void test_outbound_packet_validation() {
    Packet p;
    p.type = PayloadType::TxtMsg;
    p.payload.assign(kMaxPayloadSize, 0x55);
    CHECK(p.valid());

    p.payload.push_back(0x55);
    CHECK(!p.valid());

    p.payload.clear();
    p.path_hash_size = 2;
    p.path = {0x01};
    CHECK(!p.valid());

    p.path_hash_size = 4;
    p.path.clear();
    CHECK(!p.valid());
}

static void test_dedup_hash_ignores_path() {
    Packet a;
    a.type = PayloadType::TxtMsg;
    a.route = RouteType::Flood;
    a.payload = {1, 2, 3, 4};
    a.path = {0xaa};

    Packet b = a;
    b.path = {0xbb, 0xcc};  // repeated via a different route
    b.route = RouteType::Direct;

    // Same packet after being repeated: must still dedup.
    CHECK_BYTES(a.dedup_hash(), b.dedup_hash());

    Packet c = a;
    c.payload = {1, 2, 3, 5};
    CHECK(a.dedup_hash() != c.dedup_hash());
}

static void test_dedup_hash_covers_path_len_for_trace() {
    // A trace collects a hop per node and can legitimately come back through
    // one it already passed, so for this one type the hop count is part of the
    // identity. Everything else must stay path-blind.
    Packet a;
    a.type = PayloadType::Trace;
    a.route = RouteType::Flood;
    a.payload = {1, 2, 3, 4};
    a.path = {0xaa};

    Packet b = a;
    b.path = {0xaa, 0xbb};  // same trace, one hop further along
    CHECK(a.dedup_hash() != b.dedup_hash());

    // Same hop count on a different route is still the same packet.
    Packet c = a;
    c.path = {0xcc};
    c.route = RouteType::Direct;
    CHECK_BYTES(a.dedup_hash(), c.dedup_hash());

    // The hash size bits are part of the byte that gets mixed in.
    Packet d = a;
    d.path_hash_size = 2;
    d.path = {0xaa, 0xbb};
    CHECK(a.dedup_hash() != d.dedup_hash());
}

static void test_packed_path_len() {
    Packet p;
    p.path_hash_size = 1;
    p.path = {0xaa, 0xbb, 0xcc};
    CHECK_EQ(p.packed_path_len(), uint8_t {0x03});

    p.path_hash_size = 3;
    p.path.assign(9, 0x11);
    CHECK_EQ(p.packed_path_len(), uint8_t {0x83});

    p.path.clear();
    p.path_hash_size = 1;
    CHECK_EQ(p.packed_path_len(), uint8_t {0x00});
}

int main() {
    if (!crypto::init()) return 2;

    test_advert_packet();
    test_advert_payload();
    test_advert_appdata();
    test_advert_signature_is_rejected_when_tampered();
    test_advert_roundtrip_from_our_own_key();
    test_text_packet();
    test_text_encrypt_roundtrip();
    test_ack_packet();
    test_ack_region_of_an_empty_body_is_just_the_header();
    test_ack_region_stops_before_the_extended_attempt();
    test_padded_message_has_no_extended_attempt();
    test_ack_payload_is_unique_per_send();
    test_path_encoding();
    test_path_manipulation();
    test_transport_codes();
    test_malformed_packets_rejected();
    test_outbound_packet_validation();
    test_dedup_hash_ignores_path();
    test_dedup_hash_covers_path_len_for_trace();
    test_packed_path_len();

    return finish("packet");
}
