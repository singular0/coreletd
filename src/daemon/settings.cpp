#include "daemon/settings.h"

#include <sys/stat.h>

#include <fstream>

#include "util/ini.h"
#include "util/log.h"
#include "util/persist.h"

namespace clt {

namespace {

// The config file's syntax cuts an unquoted value at '#' or ';' and trims it,
// and keeps whatever lies between a pair of quotes, so anything that would not
// read back as written is written quoted. A name is the value that needs it.
std::string quoted(const std::string& v) {
    const bool plain = !v.empty() && v.find_first_of("#;\"'") == std::string::npos &&
                       v.front() != ' ' && v.front() != '\t' && v.back() != ' ' &&
                       v.back() != '\t';
    return plain ? v : "\"" + v + "\"";
}

bool exists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

}  // namespace

SettingsStore::SettingsStore(Config& cfg) : cfg_(cfg), path_(cfg.settings_path()) {}

void SettingsStore::attach(mesh::Node& node, mesh::Dispatcher& dispatcher) {
    node_ = &node;
    dispatcher_ = &dispatcher;
}

bool SettingsStore::load(std::string& error) {
    if (!exists(path_)) return true;

    Ini ini;
    if (!ini.load(path_, error)) return false;

    for (const auto& [key, value] : ini.entries()) {
        if (!Config::app_key(key)) {
            LOG_WARN("settings: unknown key \"%s\" ignored", key.c_str());
            continue;
        }
        if (!cfg_.set(key, value, error)) {
            error = path_ + ": " + error;
            return false;
        }
        stored_[key] = cfg_.get(key);
    }
    if (!cfg_.validate(error)) {
        error = path_ + ": " + error;
        return false;
    }

    for (const auto& [key, value] : stored_)
        LOG_DEBUG("settings: %s = %s", key.c_str(), value.c_str());
    return true;
}

companion::Settings::Result SettingsStore::set(const std::vector<Change>& changes) {
    Config next = cfg_;
    std::string error;
    for (const auto& [key, value] : changes) {
        if (!next.set(key, value, error)) {
            LOG_INFO("settings: refused from the app: %s", error.c_str());
            return Result::Invalid;
        }
    }
    if (!next.validate(error)) {
        LOG_INFO("settings: refused from the app: %s", error.c_str());
        return Result::Invalid;
    }

    Map stored = stored_;
    for (const auto& change : changes) stored[std::string(change.first)] = next.get(change.first);
    if (!save(stored, error)) {
        LOG_ERROR("settings: %s — refusing the app's change rather than applying it unsaved",
                  error.c_str());
        return Result::IoError;
    }

    for (const auto& change : changes) {
        const std::string before = cfg_.get(change.first);
        const std::string after = next.get(change.first);
        if (before == after) continue;
        LOG_INFO("settings: %.*s = %s, from the app (was %s)",
                 static_cast<int>(change.first.size()), change.first.data(), after.c_str(),
                 before.c_str());
    }
    stored_ = std::move(stored);
    cfg_ = std::move(next);
    apply();
    return Result::Ok;
}

bool SettingsStore::save(const Map& stored, std::string& error) const {
    const std::string tmp = path_ + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        error = "cannot write " + tmp;
        return false;
    }
    out << "# coreletd settings v1\n"
           "#\n"
           "# What a companion app set: only the keys it changed, the rest left at\n"
           "# their defaults. Written by the daemon; edit it only while it is stopped.\n";

    std::string section;
    for (const auto& [key, value] : stored) {
        const size_t dot = key.find('.');
        const std::string sec = key.substr(0, dot);
        if (sec != section) {
            out << "\n[" << sec << "]\n";
            section = sec;
        }
        out << key.substr(dot + 1) << " = " << quoted(value) << '\n';
    }

    out.flush();
    if (!out) {
        error = "write to " + tmp + " failed";
        return false;
    }
    out.close();
    if (!out) {
        error = "close of " + tmp + " failed";
        return false;
    }
    return durable_replace(tmp, path_, error);
}

void SettingsStore::apply() {
    if (node_) {
        node_->set_name(cfg_.node.name);
        node_->set_location(cfg_.node.lat_e6, cfg_.node.lon_e6);
        node_->set_repeat(cfg_.node.repeat);
    }
    if (dispatcher_) dispatcher_->reconfigure(cfg_.radio);
}

}  // namespace clt
