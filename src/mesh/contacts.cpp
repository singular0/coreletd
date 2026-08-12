#include "mesh/contacts.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::mesh {

const Bytes& Contact::shared_secret(const crypto::LocalIdentity& self) const {
    if (shared_.empty()) {
        if (auto s = self.shared_secret(pubkey)) shared_ = *s;
    }
    return shared_;
}

Contact* ContactStore::find(ByteView pubkey) {
    for (auto& c : contacts_)
        if (c.pubkey.size() == pubkey.size() &&
            std::equal(c.pubkey.begin(), c.pubkey.end(), pubkey.begin()))
            return &c;
    return nullptr;
}

const Contact* ContactStore::find(ByteView pubkey) const {
    return const_cast<ContactStore*>(this)->find(pubkey);
}

std::vector<Contact*> ContactStore::by_id(uint8_t id) {
    std::vector<Contact*> out;
    for (auto& c : contacts_)
        if (c.id() == id) out.push_back(&c);
    return out;
}

Contact* ContactStore::upsert(ByteView pubkey) {
    if (Contact* existing = find(pubkey)) return existing;
    if (contacts_.size() >= max_contacts_) return nullptr;
    Contact c;
    c.pubkey.assign(pubkey.begin(), pubkey.end());
    contacts_.push_back(std::move(c));
    dirty_ = true;
    return &contacts_.back();
}

Contact* ContactStore::apply_advert(const proto::Advert& adv, const proto::AdvertAppData& app,
                                    bool& created) {
    created = false;
    Contact* existing = find(adv.pubkey);

    if (existing && adv.timestamp <= existing->adv_timestamp) {
        // Not newer than what we hold: either a duplicate arriving by another
        // route, or a replay. Either way it must not overwrite anything.
        LOG_TRACE("contact %s: ignoring advert at %u (have %u)", hex_prefix(adv.pubkey).c_str(),
                  adv.timestamp, existing->adv_timestamp);
        return nullptr;
    }

    Contact* c = existing ? existing : upsert(adv.pubkey);
    if (!c) {
        LOG_WARN("contacts: limit reached, ignoring advert from %s",
                 hex_prefix(adv.pubkey).c_str());
        return nullptr;
    }
    created = existing == nullptr;

    c->adv_timestamp = adv.timestamp;
    c->last_seen = unix_now();
    c->type = app.node_type();
    c->flags = app.flags;
    if (app.has_name()) c->name = app.name;
    if (app.has_location()) {
        c->lat_e6 = app.lat_e6;
        c->lon_e6 = app.lon_e6;
    }

    // Warm the ECDH cache here rather than on the receive path: deriving the
    // shared secret costs a scalar multiplication, and an advert is a much
    // better moment to pay for it than the arrival of a message.
    c->shared_secret(self_);

    dirty_ = true;
    return c;
}

bool ContactStore::remove(ByteView pubkey) {
    auto it = std::find_if(contacts_.begin(), contacts_.end(), [&](const Contact& c) {
        return c.pubkey.size() == pubkey.size() &&
               std::equal(c.pubkey.begin(), c.pubkey.end(), pubkey.begin());
    });
    if (it == contacts_.end()) return false;
    contacts_.erase(it);
    dirty_ = true;
    return true;
}

namespace {
// Names come off the air as arbitrary bytes; keep the store one-record-per-line.
std::string sanitise(std::string s) {
    for (char& c : s)
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
    return s;
}
}  // namespace

bool ContactStore::save(const std::string& path) {
    std::string tmp = path + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        LOG_ERROR("contacts: cannot write %s", tmp.c_str());
        return false;
    }

    out << "# umeshcore contacts v1\n";
    out << "# pubkey\ttype\tflags\tadv_ts\tlast_seen\tlat_e6\tlon_e6\tpath\tname\n";
    for (const auto& c : contacts_) {
        out << hex(c.pubkey) << '\t' << static_cast<int>(c.type) << '\t'
            << static_cast<int>(c.flags) << '\t' << c.adv_timestamp << '\t' << c.last_seen << '\t'
            << c.lat_e6 << '\t' << c.lon_e6 << '\t'
            << (c.path_known ? (c.out_path.empty() ? "direct" : hex(c.out_path)) : "-") << '\t'
            << sanitise(c.name) << '\n';
    }
    out.close();
    if (!out) {
        LOG_ERROR("contacts: write to %s failed", tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        LOG_ERROR("contacts: cannot rename %s -> %s", tmp.c_str(), path.c_str());
        return false;
    }
    dirty_ = false;
    return true;
}

bool ContactStore::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) return false;

    contacts_.clear();
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        lineno++;
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string pubkey_hex, type, flags, adv_ts, last_seen, lat, lon, path_str, name;
        if (!std::getline(ss, pubkey_hex, '\t') || !std::getline(ss, type, '\t') ||
            !std::getline(ss, flags, '\t') || !std::getline(ss, adv_ts, '\t') ||
            !std::getline(ss, last_seen, '\t') || !std::getline(ss, lat, '\t') ||
            !std::getline(ss, lon, '\t') || !std::getline(ss, path_str, '\t')) {
            LOG_WARN("contacts: %s:%d malformed, skipping", path.c_str(), lineno);
            continue;
        }
        std::getline(ss, name);  // may legitimately be empty

        auto pubkey = unhex(pubkey_hex);
        if (!pubkey || pubkey->size() != crypto::kPubKeySize) {
            LOG_WARN("contacts: %s:%d bad public key, skipping", path.c_str(), lineno);
            continue;
        }

        Contact c;
        c.pubkey = std::move(*pubkey);
        c.name = name;
        c.type = static_cast<uint8_t>(std::strtoul(type.c_str(), nullptr, 10));
        c.flags = static_cast<uint8_t>(std::strtoul(flags.c_str(), nullptr, 10));
        c.adv_timestamp = static_cast<uint32_t>(std::strtoul(adv_ts.c_str(), nullptr, 10));
        c.last_seen = static_cast<uint32_t>(std::strtoul(last_seen.c_str(), nullptr, 10));
        c.lat_e6 = static_cast<int32_t>(std::strtol(lat.c_str(), nullptr, 10));
        c.lon_e6 = static_cast<int32_t>(std::strtol(lon.c_str(), nullptr, 10));

        if (path_str == "direct") {
            c.path_known = true;
        } else if (path_str != "-") {
            if (auto p = unhex(path_str)) {
                c.out_path = std::move(*p);
                c.path_known = true;
            }
        }
        if (contacts_.size() >= max_contacts_) {
            LOG_ERROR("contacts: %s exceeds limit of %zu", path.c_str(), max_contacts_);
            return false;
        }
        contacts_.push_back(std::move(c));
    }

    LOG_INFO("contacts: loaded %zu from %s", contacts_.size(), path.c_str());
    dirty_ = false;
    return true;
}

}  // namespace umc::mesh
