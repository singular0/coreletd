#include "mesh/channels.h"

#include <fstream>
#include <cstdlib>
#include <sstream>

#include "crypto/crypto.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::mesh {

uint8_t Channel::hash() const {
    if (secret.empty()) return 0;
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

ChannelStore::ChannelStore() {
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
}

std::vector<std::pair<size_t, Channel*>> ChannelStore::by_hash(uint8_t hash) {
    std::vector<std::pair<size_t, Channel*>> out;
    for (size_t i = 0; i < channels_.size(); i++) {
        if (channels_[i].valid() && channels_[i].hash() == hash) out.emplace_back(i, &channels_[i]);
    }
    return out;
}

bool ChannelStore::save(const std::string& path) const {
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
    out.close();
    if (!out) return false;
    return ::rename(tmp.c_str(), path.c_str()) == 0;
}

bool ChannelStore::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;

    // Start empty so a saved file with slot 0 cleared stays cleared.
    channels_.assign(kMaxChannels, Channel {});

    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string idx, key, name;
        if (!std::getline(ss, idx, '\t') || !std::getline(ss, key, '\t')) {
            LOG_WARN("channels: %s:%d malformed, skipping", path.c_str(), lineno);
            continue;
        }
        std::getline(ss, name);

        size_t i = std::strtoul(idx.c_str(), nullptr, 10);
        auto secret = unhex(key);
        if (i >= kMaxChannels || !secret || secret->empty()) {
            LOG_WARN("channels: %s:%d bad slot or key, skipping", path.c_str(), lineno);
            continue;
        }
        channels_[i].name = name;
        channels_[i].secret = std::move(*secret);
    }
    return true;
}

}  // namespace umc::mesh
