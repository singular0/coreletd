#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace clt {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;
using ByteSpan = std::span<uint8_t>;

// MeshCore puts every multi-byte integer on the wire little-endian.

// A cursor over a byte view. Every read is bounds-checked: a read that would
// run past the end consumes nothing, yields zero, and marks the reader failed.
// Failure is sticky, so a decoder can read all of its fields and test ok()
// once at the end instead of size-checking each one by hand.
class Reader {
public:
    explicit Reader(ByteView b) : b_(b) {}

    bool ok() const { return ok_; }
    // A failed read consumes nothing, so this still reports what was actually
    // there — which is what an error path wants to log.
    size_t remaining() const { return b_.size() - off_; }
    // For genuinely optional trailing fields, where absence is not an error.
    bool has(size_t n) const { return ok_ && remaining() >= n; }

    // Consumes n bytes. Returns an empty view (and fails the reader) if fewer
    // than n remain, so the result is either exactly n bytes or nothing.
    ByteView take(size_t n) {
        if (!has(n)) {
            ok_ = false;
            return {};
        }
        ByteView out = b_.subspan(off_, n);
        off_ += n;
        return out;
    }

    void skip(size_t n) { take(n); }

    uint8_t u8() {
        ByteView b = take(1);
        return b.empty() ? 0 : b[0];
    }

    uint16_t u16() {
        ByteView b = take(2);
        if (b.empty()) return 0;
        return static_cast<uint16_t>(b[0]) | static_cast<uint16_t>(b[1]) << 8;
    }

    uint32_t u32() {
        ByteView b = take(4);
        if (b.empty()) return 0;
        return static_cast<uint32_t>(b[0]) | static_cast<uint32_t>(b[1]) << 8 |
               static_cast<uint32_t>(b[2]) << 16 | static_cast<uint32_t>(b[3]) << 24;
    }

    int32_t i32() { return static_cast<int32_t>(u32()); }

    // Consumes a fixed-width field and returns it up to the first NUL, as the
    // companion protocol encodes names.
    std::string fixed_str(size_t width) {
        ByteView b = take(width);
        if (b.empty()) return {};
        size_t n = 0;
        while (n < b.size() && b[n] != 0) n++;
        return std::string(reinterpret_cast<const char*>(b.data()), n);
    }

    // Consumes and returns everything left, which for most payloads is a
    // trailing variable-length field.
    ByteView rest() { return take(remaining()); }

private:
    ByteView b_;
    size_t off_ = 0;
    bool ok_ = true;
};

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

}  // namespace clt
