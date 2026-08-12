#include "util/ini.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <fstream>

#include "util/log.h"

namespace umc {

namespace {

std::string_view trim(std::string_view s) {
    auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && is_space(s.front())) s.remove_prefix(1);
    while (!s.empty() && is_space(s.back())) s.remove_suffix(1);
    return s;
}

// Strip an unquoted trailing comment, then surrounding quotes if present. A
// quoted value keeps any `#` inside it, which matters for passwords.
std::string clean_value(std::string_view v) {
    v = trim(v);
    if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front())
        return std::string(v.substr(1, v.size() - 2));
    size_t cut = v.find_first_of("#;");
    if (cut != std::string_view::npos) v = trim(v.substr(0, cut));
    return std::string(v);
}

}  // namespace

bool Ini::load(const std::string& path, std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }

    std::string line, section;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        std::string_view s = trim(line);
        if (s.empty() || s.front() == '#' || s.front() == ';') continue;

        if (s.front() == '[') {
            size_t end = s.find(']');
            if (end == std::string_view::npos) {
                error = path + ":" + std::to_string(lineno) + ": unterminated section header";
                return false;
            }
            section = std::string(trim(s.substr(1, end - 1)));
            continue;
        }

        size_t eq = s.find('=');
        if (eq == std::string_view::npos) {
            error = path + ":" + std::to_string(lineno) + ": expected `key = value`";
            return false;
        }

        std::string key(trim(s.substr(0, eq)));
        if (key.empty()) {
            error = path + ":" + std::to_string(lineno) + ": empty key";
            return false;
        }
        if (!section.empty()) key = section + "." + key;
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        entries_[std::move(key)] = clean_value(s.substr(eq + 1));
    }
    return true;
}

void Ini::set(std::string key, std::string value) {
    std::transform(key.begin(), key.end(), key.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    entries_[std::move(key)] = std::move(value);
}

const std::string* Ini::find(std::string_view key) const {
    read_.emplace_back(key);
    auto it = entries_.find(key);
    return it == entries_.end() ? nullptr : &it->second;
}

bool Ini::has(std::string_view key) const { return find(key) != nullptr; }

std::string Ini::get_str(std::string_view key, std::string_view def) const {
    const std::string* v = find(key);
    return v && !v->empty() ? *v : std::string(def);
}

long Ini::get_int(std::string_view key, long def, bool& ok) const {
    ok = true;
    const std::string* v = find(key);
    if (!v || v->empty()) return def;
    errno = 0;
    char* end = nullptr;
    long out = std::strtol(v->c_str(), &end, 0);
    if (errno != 0 || end == v->c_str() || *end != '\0') {
        ok = false;
        return def;
    }
    return out;
}

int64_t Ini::get_int64(std::string_view key, int64_t def, bool& ok) const {
    ok = true;
    const std::string* v = find(key);
    if (!v || v->empty()) return def;
    errno = 0;
    char* end = nullptr;
    long long out = std::strtoll(v->c_str(), &end, 0);
    if (errno != 0 || end == v->c_str() || *end != '\0') {
        ok = false;
        return def;
    }
    return static_cast<int64_t>(out);
}

double Ini::get_double(std::string_view key, double def, bool& ok) const {
    ok = true;
    const std::string* v = find(key);
    if (!v || v->empty()) return def;
    errno = 0;
    char* end = nullptr;
    double out = std::strtod(v->c_str(), &end);
    if (errno != 0 || end == v->c_str() || *end != '\0') {
        ok = false;
        return def;
    }
    return out;
}

bool Ini::get_bool(std::string_view key, bool def, bool& ok) const {
    ok = true;
    const std::string* v = find(key);
    if (!v || v->empty()) return def;
    std::string s = *v;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s == "1" || s == "true" || s == "yes" || s == "on") return true;
    if (s == "0" || s == "false" || s == "no" || s == "off") return false;
    ok = false;
    return def;
}

long Ini::get_int(std::string_view key, long def) const {
    bool ok = true;
    long v = get_int(key, def, ok);
    if (!ok) LOG_WARN("config: %.*s is not an integer, using default", (int)key.size(), key.data());
    return v;
}

double Ini::get_double(std::string_view key, double def) const {
    bool ok = true;
    double v = get_double(key, def, ok);
    if (!ok) LOG_WARN("config: %.*s is not a number, using default", (int)key.size(), key.data());
    return v;
}

bool Ini::get_bool(std::string_view key, bool def) const {
    bool ok = true;
    bool v = get_bool(key, def, ok);
    if (!ok) LOG_WARN("config: %.*s is not a boolean, using default", (int)key.size(), key.data());
    return v;
}

std::vector<std::string> Ini::unread_keys() const {
    std::vector<std::string> out;
    for (const auto& [k, v] : entries_) {
        if (std::find(read_.begin(), read_.end(), k) == read_.end()) out.push_back(k);
    }
    return out;
}

}  // namespace umc
