#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace clt {

// Flat `key = value` config, matching the shape of the MeshCore Linux port's
// meshcored.ini. `[section]` headers are supported and simply prefix subsequent
// keys as `section.key`, so a flat file and a sectioned one can coexist.
class Ini {
public:
    // Returns false and fills `error` on unreadable file or malformed line.
    bool load(const std::string& path, std::string& error);
    void set(std::string key, std::string value);

    bool has(std::string_view key) const;

    std::string get_str(std::string_view key, std::string_view def = {}) const;
    // Parse failures are reported through `ok` rather than silently defaulting,
    // so a typo'd pin number is a startup error instead of a dead radio.
    long get_int(std::string_view key, long def, bool& ok) const;
    int64_t get_int64(std::string_view key, int64_t def, bool& ok) const;
    double get_double(std::string_view key, double def, bool& ok) const;
    bool get_bool(std::string_view key, bool def, bool& ok) const;

    long get_int(std::string_view key, long def) const;
    double get_double(std::string_view key, double def) const;
    bool get_bool(std::string_view key, bool def) const;

    // Keys present in the file that nothing ever read — almost always a typo.
    std::vector<std::string> unread_keys() const;

    const std::map<std::string, std::string, std::less<>>& entries() const { return entries_; }

private:
    const std::string* find(std::string_view key) const;

    std::map<std::string, std::string, std::less<>> entries_;
    mutable std::vector<std::string> read_;
};

}  // namespace clt
