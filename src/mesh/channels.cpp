#include "mesh/channels.h"

#include <array>
#include <charconv>
#include <fstream>
#include <string_view>

#include "crypto/crypto.h"
#include "util/hex.h"
#include "util/log.h"
#include "util/persist.h"

namespace umc::mesh {

uint8_t Channel::hash() const {
    if (!valid()) return 0;
    return crypto::sha256(secret)[0];
}

Channel Channel::from_hashtag(const std::string& name) {
    Channel ch;
    ch.name = name;
    // The '#' is part of the hashed name, so `#jokes` and `jokes` differ.
    Bytes digest = crypto::sha256(to_bytes(name));
    ch.secret.assign(digest.begin(), digest.begin() + 16);
    return ch;
}

Channel Channel::public_channel() {
    Channel ch;
    ch.name = "Public";
    if (auto key = unhex(kPublicChannelKeyHex)) ch.secret = *key;
    return ch;
}

ChannelStore::ChannelStore(std::string path) : path_(std::move(path)) {
    channels_.resize(kMaxChannels);
    channels_[0] = Channel::public_channel();
}

Channel* ChannelStore::at(size_t index) {
    return index < channels_.size() ? &channels_[index] : nullptr;
}

const Channel* ChannelStore::at(size_t index) const {
    return index < channels_.size() ? &channels_[index] : nullptr;
}

void ChannelStore::set(size_t index, Channel ch) {
    if (index >= channels_.size()) return;
    channels_[index] = std::move(ch);
    dirty_ = true;
}

std::vector<std::pair<size_t, Channel*>> ChannelStore::by_hash(uint8_t hash) {
    std::vector<std::pair<size_t, Channel*>> out;
    for (size_t i = 0; i < channels_.size(); i++) {
        if (channels_[i].valid() && channels_[i].hash() == hash) out.emplace_back(i, &channels_[i]);
    }
    return out;
}

bool ChannelStore::save() {
    if (path_.empty()) {
        LOG_ERROR("channels: asked to save a store with no path");
        return false;
    }
    const std::string& path = path_;
    std::string tmp = path + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        LOG_ERROR("channels: cannot write %s", tmp.c_str());
        return false;
    }
    out << "# umeshcore channels v1\n# index\tkey\tname\n";
    for (size_t i = 0; i < channels_.size(); i++) {
        if (!channels_[i].valid()) continue;
        std::string name = channels_[i].name;
        for (char& c : name)
            if (c == '\t' || c == '\n' || c == '\r') c = ' ';
        out << i << '\t' << hex(channels_[i].secret) << '\t' << name << '\n';
    }
    out.flush();
    if (!out) {
        LOG_ERROR("channels: write to %s failed", tmp.c_str());
        return false;
    }
    out.close();
    if (!out) {
        LOG_ERROR("channels: close of %s failed", tmp.c_str());
        return false;
    }
    std::string error;
    if (!durable_replace(tmp, path, error)) {
        LOG_ERROR("channels: %s", error.c_str());
        return false;
    }
    dirty_ = false;
    return true;
}

bool ChannelStore::load() {
    if (path_.empty()) return false;
    const std::string& path = path_;
    std::ifstream in(path);
    if (!in) return false;

    // Start empty so a saved file with slot 0 cleared stays cleared.
    std::vector<Channel> loaded(kMaxChannels);
    std::array<bool, kMaxChannels> occupied {};

    std::string line;
    int lineno = 0;
    bool saw_header = false;
    while (std::getline(in, line)) {
        lineno++;
        if (line == "# umeshcore channels v1") {
            saw_header = true;
            continue;
        }
        if (line.empty() || line[0] == '#') continue;

        auto fail = [&](const char* why) {
            LOG_ERROR("channels: %s:%d %s", path.c_str(), lineno, why);
            return false;
        };

        size_t first_tab = line.find('\t');
        size_t second_tab = first_tab == std::string::npos
                                ? std::string::npos
                                : line.find('\t', first_tab + 1);
        if (first_tab == std::string::npos || second_tab == std::string::npos ||
            line.find('\t', second_tab + 1) != std::string::npos)
            return fail("malformed record");

        std::string_view idx(line.data(), first_tab);
        std::string_view key(line.data() + first_tab + 1, second_tab - first_tab - 1);
        std::string_view name(line.data() + second_tab + 1, line.size() - second_tab - 1);

        size_t slot = 0;
        auto [end, ec] = std::from_chars(idx.data(), idx.data() + idx.size(), slot, 10);
        if (idx.empty() || ec != std::errc {} || end != idx.data() + idx.size() ||
            slot >= kMaxChannels)
            return fail("invalid slot");
        if (occupied[slot]) return fail("duplicate slot");

        auto secret = unhex(key);
        if (!secret || secret->size() != 16) return fail("channel key must be 16 bytes");

        loaded[slot].name = name;
        loaded[slot].secret = std::move(*secret);
        occupied[slot] = true;
    }
    if (in.bad()) {
        LOG_ERROR("channels: read from %s failed", path.c_str());
        return false;
    }
    if (!saw_header) {
        LOG_ERROR("channels: %s has no valid format header", path.c_str());
        return false;
    }

    channels_ = std::move(loaded);
    dirty_ = false;
    return true;
}

}  // namespace umc::mesh
