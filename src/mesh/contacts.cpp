#include "mesh/contacts.h"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <limits>
#include <string_view>

#include "mesh/record.h"
#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"
#include "util/persist.h"

namespace clt::mesh {

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

void ContactStore::touch(Contact& c) {
    c.last_seen = unix_now();
    dirty_ = true;
}

void ContactStore::touch(Contact& c, int rssi, float snr) {
    // Signal quality is not persisted, but last_seen is, so this always leaves
    // something worth writing out.
    c.last_rssi = rssi;
    c.last_snr = snr;
    touch(c);
}

bool ContactStore::set_path(Contact& c, ByteView path) {
    if (c.path_known && c.out_path.size() == path.size() &&
        std::equal(c.out_path.begin(), c.out_path.end(), path.begin()))
        return false;
    c.out_path.assign(path.begin(), path.end());
    c.path_known = true;
    dirty_ = true;
    return true;
}

bool ContactStore::clear_path(Contact& c) {
    if (!c.path_known && c.out_path.empty()) return false;
    c.out_path.clear();
    c.path_known = false;
    dirty_ = true;
    return true;
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

bool ContactStore::save() {
    if (path_.empty()) {
        LOG_ERROR("contacts: asked to save a store with no path");
        return false;
    }
    const std::string& path = path_;
    std::string tmp = path + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        LOG_ERROR("contacts: cannot write %s", tmp.c_str());
        return false;
    }

    out << "# coreletd contacts v1\n";
    out << "# pubkey\ttype\tflags\tadv_ts\tlast_seen\tlat_e6\tlon_e6\tpath\tname\n";
    for (const auto& c : contacts_) {
        out << hex(c.pubkey) << '\t' << static_cast<int>(c.type) << '\t'
            << static_cast<int>(c.flags) << '\t' << c.adv_timestamp << '\t' << c.last_seen << '\t'
            << c.lat_e6 << '\t' << c.lon_e6 << '\t'
            << (c.path_known ? (c.out_path.empty() ? "direct" : hex(c.out_path)) : "-") << '\t'
            << sanitise(c.name) << '\n';
    }
    out.flush();
    if (!out) {
        LOG_ERROR("contacts: write to %s failed", tmp.c_str());
        return false;
    }
    out.close();
    if (!out) {
        LOG_ERROR("contacts: close of %s failed", tmp.c_str());
        return false;
    }
    std::string error;
    if (!durable_replace(tmp, path, error)) {
        LOG_ERROR("contacts: %s", error.c_str());
        return false;
    }
    dirty_ = false;
    return true;
}

bool ContactStore::load() {
    if (path_.empty()) return false;
    const std::string& path = path_;
    std::ifstream in(path);
    if (!in) return false;

    std::deque<Contact> loaded;
    std::string line;
    int lineno = 0;
    bool saw_header = false;
    while (std::getline(in, line)) {
        lineno++;
        if (line == "# coreletd contacts v1") {
            saw_header = true;
            continue;
        }
        if (line.empty() || line[0] == '#') continue;

        auto fail = [&](const char* why) {
            LOG_ERROR("contacts: %s:%d %s", path.c_str(), lineno, why);
            return false;
        };

        std::vector<std::string_view> fields;
        if (!split_fields(line, 9, fields)) return fail("malformed record");

        auto pubkey = unhex(fields[0]);
        if (!pubkey || pubkey->size() != crypto::kPubKeySize) {
            return fail("invalid public key");
        }
        if (std::any_of(loaded.begin(), loaded.end(), [&](const Contact& c) {
                return crypto::equal(c.pubkey, *pubkey);
            }))
            return fail("duplicate public key");

        uint64_t type = 0, flags = 0, adv_timestamp = 0, last_seen = 0;
        int64_t lat = 0, lon = 0;
        if (!parse_unsigned(fields[1], std::numeric_limits<uint8_t>::max(), type) ||
            !parse_unsigned(fields[2], std::numeric_limits<uint8_t>::max(), flags) ||
            !parse_unsigned(fields[3], std::numeric_limits<uint32_t>::max(), adv_timestamp) ||
            !parse_unsigned(fields[4], std::numeric_limits<uint32_t>::max(), last_seen) ||
            !parse_signed(fields[5], -90000000, 90000000, lat) ||
            !parse_signed(fields[6], -180000000, 180000000, lon))
            return fail("invalid numeric field");

        Contact c;
        c.pubkey = std::move(*pubkey);
        c.name = fields[8];
        c.type = static_cast<uint8_t>(type);
        c.flags = static_cast<uint8_t>(flags);
        c.adv_timestamp = static_cast<uint32_t>(adv_timestamp);
        c.last_seen = static_cast<uint32_t>(last_seen);
        c.lat_e6 = static_cast<int32_t>(lat);
        c.lon_e6 = static_cast<int32_t>(lon);

        if (fields[7] == "direct") {
            c.path_known = true;
        } else if (fields[7] != "-") {
            auto parsed_path = unhex(fields[7]);
            if (!parsed_path || parsed_path->empty() ||
                parsed_path->size() > proto::kMaxPathSize)
                return fail("invalid path");
            c.out_path = std::move(*parsed_path);
            c.path_known = true;
        }
        if (loaded.size() >= max_contacts_) return fail("contact limit exceeded");
        loaded.push_back(std::move(c));
    }
    if (in.bad()) {
        LOG_ERROR("contacts: read from %s failed", path.c_str());
        return false;
    }
    if (!saw_header) {
        LOG_ERROR("contacts: %s has no valid format header", path.c_str());
        return false;
    }

    contacts_ = std::move(loaded);
    dirty_ = false;
    LOG_INFO("contacts: loaded %zu from %s", contacts_.size(), path.c_str());
    return true;
}

}  // namespace clt::mesh
