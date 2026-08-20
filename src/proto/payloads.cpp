#include "proto/payloads.h"

#include "crypto/crypto.h"
#include "util/hex.h"
#include "util/log.h"

namespace clt::proto {

// ---------------------------------------------------------------------------
// Advert
// ---------------------------------------------------------------------------

Bytes AdvertAppData::encode() const {
    Bytes out;
    out.push_back(flags);
    if (flags & kAdvHasLocation) {
        put_i32(out, lat_e6);
        put_i32(out, lon_e6);
    }
    if (flags & kAdvHasFeature1) put_u16(out, feature1);
    if (flags & kAdvHasFeature2) put_u16(out, feature2);
    if (flags & kAdvHasName) put_str(out, name);
    return out;
}

std::optional<AdvertAppData> AdvertAppData::decode(ByteView data) {
    Reader r(data);

    AdvertAppData app;
    app.flags = r.u8();
    if (app.flags & kAdvHasLocation) {
        app.lat_e6 = r.i32();
        app.lon_e6 = r.i32();
    }
    if (app.flags & kAdvHasFeature1) app.feature1 = r.u16();
    if (app.flags & kAdvHasFeature2) app.feature2 = r.u16();
    if (!r.ok()) return std::nullopt;

    // The name runs to the end of the appdata and is not NUL-terminated.
    if (app.flags & kAdvHasName) app.name = to_string(r.rest());
    return app;
}

std::optional<Advert> Advert::decode(ByteView payload) {
    constexpr size_t kFixed = crypto::kPubKeySize + 4 + crypto::kSignatureSize;

    Reader r(payload);
    ByteView pubkey = r.take(crypto::kPubKeySize);
    uint32_t timestamp = r.u32();
    ByteView signature = r.take(crypto::kSignatureSize);
    if (!r.ok()) {
        LOG_DEBUG("advert: payload too short (%zu < %zu)", payload.size(), kFixed);
        return std::nullopt;
    }
    ByteView appdata = r.rest();

    Advert a;
    a.pubkey.assign(pubkey.begin(), pubkey.end());
    a.timestamp = timestamp;
    a.signature.assign(signature.begin(), signature.end());
    a.appdata.assign(appdata.begin(), appdata.end());
    return a;
}

Bytes Advert::encode() const {
    Bytes out;
    out.reserve(crypto::kPubKeySize + 4 + crypto::kSignatureSize + appdata.size());
    put_bytes(out, pubkey);
    put_u32(out, timestamp);
    put_bytes(out, signature);
    put_bytes(out, appdata);
    return out;
}

Bytes Advert::signed_region(ByteView pubkey, uint32_t timestamp, ByteView appdata) {
    Bytes msg;
    msg.reserve(pubkey.size() + 4 + appdata.size());
    put_bytes(msg, pubkey);
    put_u32(msg, timestamp);
    put_bytes(msg, appdata);
    return msg;
}

bool Advert::verify() const {
    if (pubkey.size() != crypto::kPubKeySize || signature.size() != crypto::kSignatureSize)
        return false;
    return crypto::verify(pubkey, signed_region(pubkey, timestamp, appdata), signature);
}

Advert Advert::create(const crypto::LocalIdentity& self, uint32_t timestamp,
                      const AdvertAppData& app) {
    Advert a;
    a.pubkey.assign(self.pub().begin(), self.pub().end());
    a.timestamp = timestamp;
    a.appdata = app.encode();
    a.signature = self.sign(signed_region(a.pubkey, a.timestamp, a.appdata));
    return a;
}

// ---------------------------------------------------------------------------
// Envelopes
// ---------------------------------------------------------------------------

std::optional<DirectEnvelope> DirectEnvelope::decode(ByteView payload) {
    Reader r(payload);
    DirectEnvelope e;
    e.dest_hash = r.u8();
    e.src_hash = r.u8();
    ByteView mac = r.take(crypto::kCipherMacSize);
    ByteView ciphertext = r.rest();
    // An envelope with no ciphertext carries nothing to open.
    if (!r.ok() || ciphertext.empty()) return std::nullopt;

    e.mac.assign(mac.begin(), mac.end());
    e.ciphertext.assign(ciphertext.begin(), ciphertext.end());
    return e;
}

Bytes DirectEnvelope::encode() const {
    Bytes out;
    out.reserve(2 + mac.size() + ciphertext.size());
    out.push_back(dest_hash);
    out.push_back(src_hash);
    put_bytes(out, mac);
    put_bytes(out, ciphertext);
    return out;
}

DirectEnvelope DirectEnvelope::seal(uint8_t dest_hash, uint8_t src_hash, ByteView key,
                                    ByteView plaintext) {
    DirectEnvelope e;
    e.dest_hash = dest_hash;
    e.src_hash = src_hash;
    Bytes sealed = crypto::encrypt_and_mac(key, plaintext);
    if (sealed.size() >= crypto::kCipherMacSize) {
        e.mac.assign(sealed.begin(), sealed.begin() + crypto::kCipherMacSize);
        e.ciphertext.assign(sealed.begin() + crypto::kCipherMacSize, sealed.end());
    }
    return e;
}

std::optional<AnonReqEnvelope> AnonReqEnvelope::decode(ByteView payload) {
    Reader r(payload);
    AnonReqEnvelope e;
    e.dest_hash = r.u8();
    ByteView pubkey = r.take(crypto::kPubKeySize);
    ByteView mac = r.take(crypto::kCipherMacSize);
    ByteView ciphertext = r.rest();
    if (!r.ok() || ciphertext.empty()) return std::nullopt;

    e.pubkey.assign(pubkey.begin(), pubkey.end());
    e.mac.assign(mac.begin(), mac.end());
    e.ciphertext.assign(ciphertext.begin(), ciphertext.end());
    return e;
}

Bytes AnonReqEnvelope::encode() const {
    Bytes out;
    out.reserve(1 + pubkey.size() + mac.size() + ciphertext.size());
    out.push_back(dest_hash);
    put_bytes(out, pubkey);
    put_bytes(out, mac);
    put_bytes(out, ciphertext);
    return out;
}

AnonReqEnvelope AnonReqEnvelope::seal(uint8_t dest_hash, ByteView sender_pub, ByteView key,
                                      ByteView plaintext) {
    AnonReqEnvelope e;
    e.dest_hash = dest_hash;
    e.pubkey.assign(sender_pub.begin(), sender_pub.end());
    Bytes sealed = crypto::encrypt_and_mac(key, plaintext);
    if (sealed.size() >= crypto::kCipherMacSize) {
        e.mac.assign(sealed.begin(), sealed.begin() + crypto::kCipherMacSize);
        e.ciphertext.assign(sealed.begin() + crypto::kCipherMacSize, sealed.end());
    }
    return e;
}

std::optional<GroupEnvelope> GroupEnvelope::decode(ByteView payload) {
    Reader r(payload);
    GroupEnvelope e;
    e.channel_hash = r.u8();
    ByteView mac = r.take(crypto::kCipherMacSize);
    ByteView ciphertext = r.rest();
    if (!r.ok() || ciphertext.empty()) return std::nullopt;

    e.mac.assign(mac.begin(), mac.end());
    e.ciphertext.assign(ciphertext.begin(), ciphertext.end());
    return e;
}

Bytes GroupEnvelope::encode() const {
    Bytes out;
    out.reserve(1 + mac.size() + ciphertext.size());
    out.push_back(channel_hash);
    put_bytes(out, mac);
    put_bytes(out, ciphertext);
    return out;
}

GroupEnvelope GroupEnvelope::seal(uint8_t channel_hash, ByteView key, ByteView plaintext) {
    GroupEnvelope e;
    e.channel_hash = channel_hash;
    Bytes sealed = crypto::encrypt_and_mac(key, plaintext);
    if (sealed.size() >= crypto::kCipherMacSize) {
        e.mac.assign(sealed.begin(), sealed.begin() + crypto::kCipherMacSize);
        e.ciphertext.assign(sealed.begin() + crypto::kCipherMacSize, sealed.end());
    }
    return e;
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

std::optional<TextMessage> TextMessage::decode(ByteView plaintext) {
    Reader r(plaintext);
    uint32_t timestamp = r.u32();
    uint8_t type_and_attempt = r.u8();
    if (!r.ok()) return std::nullopt;

    TextMessage m;
    m.timestamp = timestamp;
    // Upper six bits are the type, lower two the retry attempt.
    m.txt_type = static_cast<uint8_t>(type_and_attempt >> 2);
    m.attempt = static_cast<uint8_t>(type_and_attempt & 0x03);

    // The text is a C string: it ends at the first NUL, and anything after
    // that is either AES padding or the extended attempt byte. Stripping
    // trailing zeros instead would hand the app "text\0<attempt>" whenever the
    // sender was past its third try.
    ByteView rest = r.rest();
    size_t end = 0;
    while (end < rest.size() && rest[end] != 0) end++;
    m.text.assign(rest.begin(), rest.begin() + end);
    // MeshCore reads this byte unconditionally, so on a padded message it is
    // simply zero.
    if (end + 1 < rest.size()) m.extended_attempt = rest[end + 1];
    return m;
}

Bytes TextMessage::encode() const {
    Bytes out;
    out.reserve(5 + text.size());
    put_u32(out, timestamp);
    out.push_back(static_cast<uint8_t>((txt_type << 2) | (attempt & 0x03)));
    put_bytes(out, text);
    return out;
}

ByteView TextMessage::sender_prefix() const {
    if (txt_type != kTxtSignedPlain) return {};
    return subview(text, 0, 4);
}

std::string TextMessage::body() const {
    return txt_type == kTxtSignedPlain ? to_string(subview(text, 4)) : to_string(text);
}

ByteView strip_zero_padding(ByteView plaintext) {
    size_t n = plaintext.size();
    while (n > 0 && plaintext[n - 1] == 0) n--;
    return subview(plaintext, 0, n);
}

// timestamp(4) + flags(1). An empty body hashes exactly this much.
constexpr size_t kTextHeaderSize = 5;

ByteView ack_hashed_region(ByteView plaintext) {
    if (plaintext.size() <= kTextHeaderSize) return plaintext;
    size_t end = kTextHeaderSize;
    while (end < plaintext.size() && plaintext[end] != 0) end++;
    return subview(plaintext, 0, end);
}

uint8_t ack_extended_attempt(ByteView plaintext) {
    const size_t after_nul = ack_hashed_region(plaintext).size() + 1;
    return after_nul < plaintext.size() ? plaintext[after_nul] : 0;
}

Bytes message_ack_hash(ByteView plaintext, ByteView pubkey) {
    ByteView hashed = ack_hashed_region(plaintext);
    Bytes buf;
    buf.reserve(hashed.size() + pubkey.size());
    put_bytes(buf, hashed);
    put_bytes(buf, pubkey);
    return crypto::ack_hash(buf);
}

Bytes ack_payload(ByteView ack_hash, uint8_t extended_attempt) {
    Bytes out;
    out.reserve(crypto::kAckHashSize + 2);
    put_bytes(out, subview(ack_hash, 0, crypto::kAckHashSize));
    out.push_back(extended_attempt);
    uint8_t r = 0;
    crypto::random_bytes(ByteSpan(&r, 1));
    out.push_back(r);
    return out;
}

std::optional<PathReturn> PathReturn::decode(ByteView plaintext) {
    Reader r(plaintext);
    // The same packed byte the packet header carries, not a byte count: hop
    // count in bits 0-5, hash size - 1 in bits 6-7.
    const uint8_t path_len = r.u8();
    if (!r.ok()) return std::nullopt;

    PathReturn p;
    p.path_hash_size = static_cast<uint8_t>((path_len >> 6) + 1);
    if (p.path_hash_size == 4) return std::nullopt;  // reserved

    ByteView path = r.take(static_cast<size_t>(path_len & 0x3F) * p.path_hash_size);
    if (!r.ok() || path.size() > kMaxPathSize) return std::nullopt;
    p.path.assign(path.begin(), path.end());

    if (r.has(1)) {
        p.has_extra = true;
        // Only the low nibble is the payload type; the upper four bits are
        // reserved, and a sender that starts using them must not turn our ACK
        // into an unrecognised type.
        p.extra_type = static_cast<uint8_t>(r.u8() & 0x0F);
        // Whatever follows is the bundled payload; padding is the caller's
        // problem since only it knows the extra type's length.
        ByteView extra = r.rest();
        p.extra.assign(extra.begin(), extra.end());
    }
    return p;
}

Bytes PathReturn::encode() const {
    const uint8_t hash_size = path_hash_size ? path_hash_size : 1;
    const size_t hops = path.size() / hash_size;

    Bytes out;
    out.reserve(1 + path.size() + 1 + extra.size());
    out.push_back(static_cast<uint8_t>((hops & 0x3F) | ((hash_size - 1) << 6)));
    put_bytes(out, path);
    if (has_extra) {
        out.push_back(static_cast<uint8_t>(extra_type & 0x0F));
        put_bytes(out, extra);
    }
    return out;
}

}  // namespace clt::proto
