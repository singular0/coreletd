#pragma once

#include <optional>

#include "util/bytes.h"

namespace umc::proto {

// Wire limits from the MeshCore packet format. Firmware <= v1.12.0 drops
// packets that exceed either, so we must never generate one that does.
inline constexpr size_t kMaxPathSize = 64;
inline constexpr size_t kMaxPayloadSize = 184;
inline constexpr size_t kMaxPacketSize = 255;

enum class RouteType : uint8_t {
    TransportFlood = 0x00,
    Flood = 0x01,
    Direct = 0x02,
    TransportDirect = 0x03,
};

enum class PayloadType : uint8_t {
    Req = 0x00,
    Response = 0x01,
    TxtMsg = 0x02,
    Ack = 0x03,
    Advert = 0x04,
    GrpTxt = 0x05,
    GrpData = 0x06,
    AnonReq = 0x07,
    Path = 0x08,
    Trace = 0x09,
    Multipart = 0x0A,
    Control = 0x0B,
    RawCustom = 0x0F,
};

const char* route_type_name(RouteType t);
const char* payload_type_name(PayloadType t);

// header byte: 0bVVPPPPRR — version(2) | payload type(4) | route type(2)
inline constexpr uint8_t kRouteMask = 0x03;
inline constexpr uint8_t kPayloadTypeMask = 0x3C;
inline constexpr uint8_t kPayloadVerMask = 0xC0;

struct Packet {
    uint8_t payload_version = 0;  // 0 == v1: 1-byte hashes, 2-byte MAC
    RouteType route = RouteType::Flood;
    PayloadType type = PayloadType::Advert;

    // Only present on the TRANSPORT_* route types.
    uint16_t transport_code1 = 0;
    uint16_t transport_code2 = 0;

    // Path hashes are 1..3 bytes each; `path` holds hop_count * hash_size bytes.
    uint8_t path_hash_size = 1;
    Bytes path;
    Bytes payload;

    // Receive metadata. Not on the wire; used for routing decisions, the
    // companion app's signal display, and log output.
    int rssi = 0;
    float snr = 0.0f;
    uint32_t rx_millis = 0;
    // Set for packets we generated or looped back internally, so the
    // originating device can drop its own echo.
    bool internal = false;

    bool has_transport_codes() const {
        return route == RouteType::TransportFlood || route == RouteType::TransportDirect;
    }
    bool is_flood() const {
        return route == RouteType::Flood || route == RouteType::TransportFlood;
    }
    bool is_direct() const {
        return route == RouteType::Direct || route == RouteType::TransportDirect;
    }

    size_t hop_count() const { return path_hash_size ? path.size() / path_hash_size : 0; }

    // Appends one hop. Returns false if the path is already full, in which case
    // the packet must not be repeated any further.
    bool push_hop(ByteView hash);
    // First hop on the path, i.e. the next node a direct-routed packet is for.
    ByteView first_hop() const;
    // Drops the leading hop, consuming it as we forward a direct-routed packet.
    void pop_hop();

    static std::optional<Packet> decode(ByteView raw);
    Bytes encode() const;

    // Dedup key: covers the header type bits and the payload, but deliberately
    // not the path — a repeated packet mutates its path at every hop and must
    // still be recognised as the same packet.
    Bytes dedup_hash() const;

    std::string describe() const;
};

}  // namespace umc::proto
