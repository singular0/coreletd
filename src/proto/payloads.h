#pragma once

#include <optional>
#include <string>

#include "crypto/identity.h"
#include "proto/packet.h"
#include "util/bytes.h"

namespace umc::proto {

// ---------------------------------------------------------------------------
// Node advertisement
// ---------------------------------------------------------------------------

// The low nibble of the appdata flags is a node *type*, not a bit field:
// 0x03 (room server) is a value, not chat|repeater.
// Plain constants rather than two enums: the node type and the presence flags
// share one byte and are routinely OR'd together.
inline constexpr uint8_t kAdvTypeNone = 0x00;
inline constexpr uint8_t kAdvTypeChat = 0x01;
inline constexpr uint8_t kAdvTypeRepeater = 0x02;
inline constexpr uint8_t kAdvTypeRoom = 0x03;
inline constexpr uint8_t kAdvTypeSensor = 0x04;
inline constexpr uint8_t kAdvTypeMask = 0x0F;

inline constexpr uint8_t kAdvHasLocation = 0x10;
inline constexpr uint8_t kAdvHasFeature1 = 0x20;
inline constexpr uint8_t kAdvHasFeature2 = 0x40;
inline constexpr uint8_t kAdvHasName = 0x80;

struct AdvertAppData {
    uint8_t flags = 0;
    int32_t lat_e6 = 0;  // degrees * 1e6
    int32_t lon_e6 = 0;
    uint16_t feature1 = 0;
    uint16_t feature2 = 0;
    std::string name;

    uint8_t node_type() const { return flags & kAdvTypeMask; }
    bool has_location() const { return flags & kAdvHasLocation; }
    bool has_name() const { return flags & kAdvHasName; }

    Bytes encode() const;
    static std::optional<AdvertAppData> decode(ByteView data);
};

struct Advert {
    Bytes pubkey;     // 32
    uint32_t timestamp = 0;
    Bytes signature;  // 64
    Bytes appdata;    // raw, still encoded

    static std::optional<Advert> decode(ByteView payload);
    Bytes encode() const;

    // What the Ed25519 signature covers: pubkey || timestamp(LE) || appdata.
    static Bytes signed_region(ByteView pubkey, uint32_t timestamp, ByteView appdata);
    bool verify() const;

    static Advert create(const crypto::LocalIdentity& self, uint32_t timestamp,
                         const AdvertAppData& app);
};

// ---------------------------------------------------------------------------
// Encrypted envelopes
// ---------------------------------------------------------------------------

// REQ / RESPONSE / TXT_MSG / PATH all share this shape.
struct DirectEnvelope {
    uint8_t dest_hash = 0;
    uint8_t src_hash = 0;
    Bytes mac;  // 2
    Bytes ciphertext;

    static std::optional<DirectEnvelope> decode(ByteView payload);
    Bytes encode() const;
    // Seals `plaintext` under `key` and fills mac + ciphertext.
    static DirectEnvelope seal(uint8_t dest_hash, uint8_t src_hash, ByteView key,
                               ByteView plaintext);
};

struct AnonReqEnvelope {
    uint8_t dest_hash = 0;
    Bytes pubkey;  // 32, the sender's — this is what makes it anonymous-but-attributable
    Bytes mac;     // 2
    Bytes ciphertext;

    static std::optional<AnonReqEnvelope> decode(ByteView payload);
    Bytes encode() const;
    static AnonReqEnvelope seal(uint8_t dest_hash, ByteView sender_pub, ByteView key,
                                ByteView plaintext);
};

struct GroupEnvelope {
    uint8_t channel_hash = 0;
    Bytes mac;  // 2
    Bytes ciphertext;

    static std::optional<GroupEnvelope> decode(ByteView payload);
    Bytes encode() const;
    static GroupEnvelope seal(uint8_t channel_hash, ByteView key, ByteView plaintext);
};

// ---------------------------------------------------------------------------
// Decrypted payload bodies
// ---------------------------------------------------------------------------

enum TxtType : uint8_t {
    kTxtPlain = 0x00,
    kTxtCliData = 0x01,
    kTxtSignedPlain = 0x02,
};

struct TextMessage {
    uint32_t timestamp = 0;
    uint8_t txt_type = kTxtPlain;
    uint8_t attempt = 0;
    // For kTxtSignedPlain the first 4 bytes of `text` are the sender's pubkey
    // prefix; `sender_prefix()` splits it out.
    Bytes text;

    static std::optional<TextMessage> decode(ByteView plaintext);
    Bytes encode() const;

    ByteView sender_prefix() const;
    std::string body() const;
};

// Trailing zero bytes are AES padding, not message content. MeshCore strips
// them before hashing, so we must too or acks will never match.
ByteView strip_zero_padding(ByteView plaintext);

// SHA-256(plaintext_without_padding || pubkey)[0..4].
// `pubkey` is the message author's for plain text, but the *recipient's* for
// signed/room-server messages.
Bytes message_ack_hash(ByteView plaintext, ByteView pubkey);

struct PathReturn {
    Bytes path;
    // An ack or response can ride along inside a returned path instead of
    // costing a second transmission.
    uint8_t extra_type = 0;
    Bytes extra;
    bool has_extra = false;

    static std::optional<PathReturn> decode(ByteView plaintext);
    Bytes encode() const;
};

// Anonymous request bodies (repeater/room login).
struct LoginRequest {
    uint32_t timestamp = 0;
    uint32_t sync_timestamp = 0;  // room server only
    std::string password;
};

}  // namespace umc::proto
