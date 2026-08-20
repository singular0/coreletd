#pragma once

// Shared parsing for the line-per-record state files. Contacts, channels and
// the message queue all use the same shape — a version header, then tab
// separated fields — so the field splitting and the bounds-checked number
// parsing live here rather than once per store.

#include <charconv>
#include <cstdint>
#include <string_view>
#include <vector>

namespace clt::mesh {

// Splits into exactly `count` fields. A line with too few or too many is
// rejected rather than silently padded, because a short record means the file
// is from a different version or was truncated mid-write.
inline bool split_fields(std::string_view line, size_t count,
                         std::vector<std::string_view>& fields) {
    fields.clear();
    fields.reserve(count);
    for (size_t i = 1; i < count; i++) {
        size_t tab = line.find('\t');
        if (tab == std::string_view::npos) return false;
        fields.push_back(line.substr(0, tab));
        line.remove_prefix(tab + 1);
    }
    if (line.find('\t') != std::string_view::npos) return false;
    fields.push_back(line);
    return true;
}

inline bool parse_unsigned(std::string_view text, uint64_t max, uint64_t& value) {
    if (text.empty()) return false;
    uint64_t parsed = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed, 10);
    if (ec != std::errc {} || end != text.data() + text.size() || parsed > max) return false;
    value = parsed;
    return true;
}

inline bool parse_signed(std::string_view text, int64_t min, int64_t max, int64_t& value) {
    if (text.empty()) return false;
    int64_t parsed = 0;
    auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed, 10);
    if (ec != std::errc {} || end != text.data() + text.size() || parsed < min || parsed > max)
        return false;
    value = parsed;
    return true;
}

}  // namespace clt::mesh
