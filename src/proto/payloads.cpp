#include "proto/payloads.h"

#include "crypto/crypto.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::proto {

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
    if (data.empty()) return std::nullopt;

    AdvertAppData app;
    size_t off = 0;
    app.flags = data[off++];

    auto need = [&](size_t n) { return data.size() >= off + n; };

    if (app.flags & kAdvHasLocation) {
        if (!need(8)) return std::nullopt;
        app.lat_e6 = rd_i32(data, off);
        app.lon_e6 = rd_i32(data, off + 4);
        off += 8;
    }
    if (app.flags & kAdvHasFeature1) {
        if (!need(2)) return std::nullopt;
        app.feature1 = rd_u16(data, off);
        off += 2;
    }
    if (app.flags & kAdvHasFeature2) {
        if (!need(2)) return std::nullopt;
        app.feature2 = rd_u16(data, off);
        off += 2;
    }
    // The name runs to the end of the appdata and is not NUL-terminated.
    if (app.flags & kAdvHasName) app.name = to_string(subview(data, off));
    return app;
}

std::optional<Advert> Advert::decode(ByteView payload) {
    constexpr size_t kFixed = crypto::kPubKeySize + 4 + crypto::kSignatureSize;
    if (payload.size() < kFixed) {
        LOG_DEBUG("advert: payload too short (%zu < %zu)", payload.size(), kFixed);
        return std::nullopt;
    }

    Advert a;
    a.pubkey.assign(payload.begin(), payload.begin() + crypto::kPubKeySize);
    a.timestamp = rd_u32(payload, crypto::kPubKeySize);
    a.signature.assign(payload.begin() + crypto::kPubKeySize + 4, payload.begin() + kFixed);
    a.appdata.assign(payload.begin() + kFixed, payload.end());
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
    constexpr size_t kFixed = 1 + 1 + crypto::kCipherMacSize;
    if (payload.size() <= kFixed) return std::nullopt;

    DirectEnvelope e;
    e.dest_hash = payload[0];
    e.src_hash = payload[1];
    e.mac.assign(payload.begin() + 2, payload.begin() + kFixed);
    e.ciphertext.assign(payload.begin() + kFixed, payload.end());
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
    constexpr size_t kFixed = 1 + crypto::kPubKeySize + crypto::kCipherMacSize;
    if (payload.size() <= kFixed) return std::nullopt;

    AnonReqEnvelope e;
    e.dest_hash = payload[0];
    e.pubkey.assign(payload.begin() + 1, payload.begin() + 1 + crypto::kPubKeySize);
    e.mac.assign(payload.begin() + 1 + crypto::kPubKeySize, payload.begin() + kFixed);
    e.ciphertext.assign(payload.begin() + kFixed, payload.end());
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
    constexpr size_t kFixed = 1 + crypto::kCipherMacSize;
    if (payload.size() <= kFixed) return std::nullopt;

    GroupEnvelope e;
    e.channel_hash = payload[0];
    e.mac.assign(payload.begin() + 1, payload.begin() + kFixed);
    e.ciphertext.assign(payload.begin() + kFixed, payload.end());
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
    if (plaintext.size() < 5) return std::nullopt;

    TextMessage m;
    m.timestamp = rd_u32(plaintext, 0);
    // Upper six bits are the type, lower two the retry attempt.
    m.txt_type = static_cast<uint8_t>(plaintext[4] >> 2);
    m.attempt = static_cast<uint8_t>(plaintext[4] & 0x03);

    ByteView body = strip_zero_padding(subview(plaintext, 5));
    m.text.assign(body.begin(), body.end());
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

Bytes message_ack_hash(ByteView plaintext, ByteView pubkey) {
    ByteView stripped = strip_zero_padding(plaintext);
    Bytes buf;
    buf.reserve(stripped.size() + pubkey.size());
    put_bytes(buf, stripped);
    put_bytes(buf, pubkey);
    return crypto::ack_hash(buf);
}

std::optional<PathReturn> PathReturn::decode(ByteView plaintext) {
    if (plaintext.empty()) return std::nullopt;

    PathReturn p;
    const size_t path_len = plaintext[0];
    if (plaintext.size() < 1 + path_len) return std::nullopt;
    p.path.assign(plaintext.begin() + 1, plaintext.begin() + 1 + path_len);

    size_t off = 1 + path_len;
    if (off < plaintext.size()) {
        p.has_extra = true;
        p.extra_type = plaintext[off++];
        // Whatever follows is the bundled payload; padding is the caller's
        // problem since only it knows the extra type's length.
        p.extra.assign(plaintext.begin() + off, plaintext.end());
    }
    return p;
}

Bytes PathReturn::encode() const {
    Bytes out;
    out.reserve(1 + path.size() + 1 + extra.size());
    out.push_back(static_cast<uint8_t>(path.size()));
    put_bytes(out, path);
    if (has_extra) {
        out.push_back(extra_type);
        put_bytes(out, extra);
    }
    return out;
}

}  // namespace umc::proto
