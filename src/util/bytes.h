#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace umc {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;
using ByteSpan = std::span<uint8_t>;

// MeshCore puts every multi-byte integer on the wire little-endian.

inline uint16_t rd_u16(ByteView b, size_t off = 0) {
    return static_cast<uint16_t>(b[off]) | static_cast<uint16_t>(b[off + 1]) << 8;
}

inline uint32_t rd_u32(ByteView b, size_t off = 0) {
    return static_cast<uint32_t>(b[off]) | static_cast<uint32_t>(b[off + 1]) << 8 |
           static_cast<uint32_t>(b[off + 2]) << 16 | static_cast<uint32_t>(b[off + 3]) << 24;
}

inline int32_t rd_i32(ByteView b, size_t off = 0) {
    return static_cast<int32_t>(rd_u32(b, off));
}

inline void put_u16(Bytes& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

inline void put_u32(Bytes& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 24));
}

inline void put_i32(Bytes& out, int32_t v) {
    put_u32(out, static_cast<uint32_t>(v));
}

inline void put_bytes(Bytes& out, ByteView b) {
    out.insert(out.end(), b.begin(), b.end());
}

inline void put_str(Bytes& out, std::string_view s) {
    out.insert(out.end(), s.begin(), s.end());
}

// Copy a string into a fixed-width NUL-padded field, as the companion protocol
// expects for names. Truncates rather than overflowing.
inline void put_fixed_str(Bytes& out, std::string_view s, size_t width) {
    size_t n = std::min(s.size(), width);
    out.insert(out.end(), s.begin(), s.begin() + n);
    out.insert(out.end(), width - n, 0);
}

// Read a NUL-terminated (or field-terminated) string out of a fixed-width field.
inline std::string rd_fixed_str(ByteView b, size_t off, size_t width) {
    if (off >= b.size()) return {};
    size_t avail = std::min(width, b.size() - off);
    size_t n = 0;
    while (n < avail && b[off + n] != 0) n++;
    return std::string(reinterpret_cast<const char*>(b.data() + off), n);
}

inline Bytes to_bytes(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

// Decode as UTF-8-ish text for display/logging; MeshCore names and messages are
// bytes on the wire and are not guaranteed to be valid UTF-8.
inline std::string to_string(ByteView b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

inline ByteView subview(ByteView b, size_t off) {
    if (off >= b.size()) return {};
    return b.subspan(off);
}

inline ByteView subview(ByteView b, size_t off, size_t len) {
    if (off >= b.size()) return {};
    return b.subspan(off, std::min(len, b.size() - off));
}

}  // namespace umc
