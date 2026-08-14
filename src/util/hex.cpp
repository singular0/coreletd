#include "util/hex.h"

namespace clt {

namespace {
constexpr char kDigits[] = "0123456789abcdef";

int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

std::string hex(ByteView b) {
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t c : b) {
        out.push_back(kDigits[c >> 4]);
        out.push_back(kDigits[c & 0x0f]);
    }
    return out;
}

std::string hex_prefix(ByteView b, size_t n) {
    return hex(subview(b, 0, n));
}

std::optional<Bytes> unhex(std::string_view s) {
    if (s.size() % 2 != 0) return std::nullopt;
    Bytes out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>(hi << 4 | lo));
    }
    return out;
}

}  // namespace clt
