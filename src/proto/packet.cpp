#include "proto/packet.h"

#include "crypto/crypto.h"
#include "util/hex.h"
#include "util/log.h"

namespace clt::proto {

const char* route_type_name(RouteType t) {
    switch (t) {
        case RouteType::TransportFlood: return "transport-flood";
        case RouteType::Flood: return "flood";
        case RouteType::Direct: return "direct";
        case RouteType::TransportDirect: return "transport-direct";
    }
    return "?";
}

const char* payload_type_name(PayloadType t) {
    switch (t) {
        case PayloadType::Req: return "REQ";
        case PayloadType::Response: return "RESPONSE";
        case PayloadType::TxtMsg: return "TXT_MSG";
        case PayloadType::Ack: return "ACK";
        case PayloadType::Advert: return "ADVERT";
        case PayloadType::GrpTxt: return "GRP_TXT";
        case PayloadType::GrpData: return "GRP_DATA";
        case PayloadType::AnonReq: return "ANON_REQ";
        case PayloadType::Path: return "PATH";
        case PayloadType::Trace: return "TRACE";
        case PayloadType::Multipart: return "MULTIPART";
        case PayloadType::Control: return "CONTROL";
        case PayloadType::RawCustom: return "RAW_CUSTOM";
    }
    return "RESERVED";
}

uint8_t Packet::packed_path_len() const {
    const uint8_t hash_size = path_hash_size ? path_hash_size : 1;
    const size_t hops = path.size() / hash_size;
    return static_cast<uint8_t>((hops & 0x3F) | ((hash_size - 1) << 6));
}

bool Packet::push_hop(ByteView hash) {
    if (path_hash_size == 0 || hash.size() < path_hash_size) return false;
    if (path.size() + path_hash_size > kMaxPathSize) return false;
    // Hop count is 6 bits, so 63 hops is the hard ceiling regardless of size.
    if (hop_count() >= 63) return false;
    path.insert(path.end(), hash.begin(), hash.begin() + path_hash_size);
    return true;
}

ByteView Packet::first_hop() const {
    if (path.size() < path_hash_size) return {};
    return ByteView(path).subspan(0, path_hash_size);
}

void Packet::pop_hop() {
    if (path.size() < path_hash_size) {
        path.clear();
        return;
    }
    path.erase(path.begin(), path.begin() + path_hash_size);
}

std::optional<Packet> Packet::decode(ByteView raw) {
    Reader r(raw);

    Packet p;
    const uint8_t header = r.u8();
    if (!r.ok()) return std::nullopt;
    p.route = static_cast<RouteType>(header & kRouteMask);
    p.type = static_cast<PayloadType>((header & kPayloadTypeMask) >> 2);
    p.payload_version = static_cast<uint8_t>((header & kPayloadVerMask) >> 6);

    // v2 is reserved for 2-byte source/destination hashes and a 4-byte MAC, and
    // nothing below this line reads the version: the envelope codecs are v1
    // shaped whatever it says. Parsing a v2 packet as v1 would mis-slice it into
    // a failed MAC check and then repeat it under a v1 dedup hash, so refuse it
    // here as MeshCore's Dispatcher::tryParsePacket does.
    if (p.payload_version > 0) {
        LOG_DEBUG("packet: unsupported payload version %u", p.payload_version);
        return std::nullopt;
    }

    if (p.has_transport_codes()) {
        p.transport_code1 = r.u16();
        p.transport_code2 = r.u16();
        if (!r.ok()) {
            LOG_DEBUG("packet: truncated transport codes");
            return std::nullopt;
        }
    }

    const uint8_t path_len = r.u8();
    if (!r.ok()) {
        LOG_DEBUG("packet: missing path length");
        return std::nullopt;
    }

    // path_length is not a byte count: bits 0-5 are the hop count and bits 6-7
    // carry (hash size - 1). The byte length is the product of the two.
    const size_t hops = path_len & 0x3F;
    p.path_hash_size = static_cast<uint8_t>(((path_len & 0xC0) >> 6) + 1);
    if (p.path_hash_size == 4) {
        LOG_DEBUG("packet: reserved path hash size");
        return std::nullopt;
    }

    const size_t path_bytes = hops * p.path_hash_size;
    if (path_bytes > kMaxPathSize) {
        LOG_DEBUG("packet: path of %zu bytes exceeds max %zu", path_bytes, kMaxPathSize);
        return std::nullopt;
    }
    ByteView path = r.take(path_bytes);
    if (!r.ok()) {
        LOG_DEBUG("packet: truncated path (want %zu, have %zu)", path_bytes, r.remaining());
        return std::nullopt;
    }
    p.path.assign(path.begin(), path.end());

    ByteView payload = r.rest();
    // MeshCore's Packet::readFrom requires at least one byte after the path;
    // every payload type has a header of its own, so an empty one is a corrupt
    // packet rather than a valid packet carrying nothing.
    if (payload.empty()) {
        LOG_DEBUG("packet: empty payload");
        return std::nullopt;
    }
    if (payload.size() > kMaxPayloadSize) {
        LOG_DEBUG("packet: payload of %zu bytes exceeds max %zu", payload.size(), kMaxPayloadSize);
        return std::nullopt;
    }
    p.payload.assign(payload.begin(), payload.end());
    return p;
}

bool Packet::valid() const {
    if (path_hash_size < 1 || path_hash_size > 3) return false;
    if (path.size() > kMaxPathSize || path.size() % path_hash_size != 0) return false;
    if (hop_count() > 63 || payload.size() > kMaxPayloadSize) return false;

    const size_t transport_bytes = has_transport_codes() ? 4 : 0;
    return 2 + transport_bytes + path.size() + payload.size() <= kMaxPacketSize;
}

Bytes Packet::encode() const {
    Bytes out;
    out.reserve(2 + 4 + path.size() + payload.size());

    const uint8_t header = static_cast<uint8_t>(static_cast<uint8_t>(route) & kRouteMask) |
                           static_cast<uint8_t>((static_cast<uint8_t>(type) << 2) & kPayloadTypeMask) |
                           static_cast<uint8_t>((payload_version << 6) & kPayloadVerMask);
    out.push_back(header);

    if (has_transport_codes()) {
        put_u16(out, transport_code1);
        put_u16(out, transport_code2);
    }

    out.push_back(packed_path_len());

    put_bytes(out, path);
    put_bytes(out, payload);
    return out;
}

Bytes Packet::dedup_hash() const {
    // Header type bits without the route type: the same packet can arrive both
    // flood-routed and direct-routed and is still a duplicate.
    Bytes buf;
    buf.reserve(3 + payload.size());
    buf.push_back(static_cast<uint8_t>(type));
    // A trace legitimately revisits a node on its return leg, so MeshCore mixes
    // path_len in for this one type to keep the two visits distinct. Its field
    // is a uint16_t, hashed whole, so the two bytes are little-endian.
    if (type == PayloadType::Trace) put_u16(buf, packed_path_len());
    put_bytes(buf, payload);
    return crypto::ack_hash(buf);
}

std::string Packet::describe() const {
    std::string s = payload_type_name(type);
    s += " ";
    s += route_type_name(route);
    s += vformat(" hops=%zu payload=%zu", hop_count(), payload.size());
    if (!path.empty()) s += " path=" + hex(path);
    return s;
}

}  // namespace clt::proto
