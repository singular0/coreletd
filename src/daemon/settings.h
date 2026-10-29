#pragma once

#include <map>
#include <string>

#include "companion/settings.h"
#include "daemon/config.h"
#include "mesh/dispatcher.h"
#include "mesh/node.h"

namespace clt {

// The settings a companion app changes — Config::app_keys() — kept in the
// state directory as MeshCore keeps them in its preferences: read over the
// defaults at startup, and applied to the running node when the app changes
// them. The config file has no say in them. It is a dpkg conffile under /etc,
// which the unit's ProtectSystem=strict makes read-only to the daemon, and a
// key with two owners needs rules for which one wins.
//
// The file holds only the keys that have been set, in the config file's
// syntax, so a node that never set one follows the default in the code. It is
// the app's to write, but an operator without one may write it by hand with
// the daemon stopped.
//
// Each change is written before it is answered, rather than coalesced through
// StateWriter: settings change a few times a session, and the reply has to be
// true.
class SettingsStore final : public companion::Settings {
public:
    // App's config. From load() on, every setting in the file and every change
    // the app makes lands in it.
    explicit SettingsStore(Config& cfg);

    // Applies the file over the defaults. Returns false with `error` set on
    // one the daemon would not have written — a value out of range, a name the
    // advert cannot carry — which is a hand edit gone wrong, and better
    // refused at startup than guessed around: the frequency is in here.
    bool load(std::string& error);

    // The subsystems a change applies to, once they exist.
    void attach(mesh::Node& node, mesh::Dispatcher& dispatcher);

    // companion::Settings
    Result set(const std::vector<Change>& changes) override;

private:
    // Each key set, and its value as Config::get() spells it.
    using Map = std::map<std::string, std::string, std::less<>>;

    bool save(const Map& stored, std::string& error) const;
    void apply();

    Config& cfg_;
    std::string path_;
    Map stored_;
    mesh::Node* node_ = nullptr;
    mesh::Dispatcher* dispatcher_ = nullptr;
};

}  // namespace clt
