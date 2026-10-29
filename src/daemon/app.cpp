#include "daemon/app.h"

#include <sys/stat.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "crypto/crypto.h"
#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"
#include "util/persist.h"
#include "version.h"  // generated: CORELETD_VERSION, resolved from git

#if CORELETD_HAVE_SX1262
#include "radio/sx1262.h"
#endif

namespace clt {

App::App(Config cfg, std::unique_ptr<radio::Radio> radio, Clock& clock)
    : cfg_(std::move(cfg)), loop_(clock), radio_(std::move(radio)) {}
App::~App() = default;

namespace {

// Loads a store, and when its file is there but unreadable, moves it aside and
// tries the copy the previous save left behind.
//
// Continuing with an empty store is the last resort rather than the first
// answer: a lost contact is a peer we can no longer decrypt until it advertises
// again, and a lost channel key is traffic we can never read. Starting the
// radio anyway is still right — the daemon exists to be on the air, and a node
// that refuses to boot helps nobody — but not before the damaged file is out of
// reach of the next save.
template <typename Store>
mesh::LoadResult load_state(Store& store, const std::string& path, const char* what) {
    mesh::LoadResult result = store.load();
    if (result != mesh::LoadResult::Corrupt) return result;

    quarantine(path);

    const std::string backup = path + ".bak";
    if (::rename(backup.c_str(), path.c_str()) != 0) {
        LOG_ERROR("%s: unreadable and no backup to fall back on; starting empty", what);
        return mesh::LoadResult::Corrupt;
    }

    result = store.load();
    if (result == mesh::LoadResult::Corrupt) {
        quarantine(path);
        LOG_ERROR("%s: the backup is unreadable too; starting empty", what);
        return result;
    }
    LOG_WARN("%s: recovered from the copy taken before the last save", what);
    return result;
}

// Every save is written 0600, but a file restored from a backup, or left by an
// older version, is restricted here rather than at its next save — which, for
// a channel list nobody edits, may never come. The backup and the temporary a
// crashed save leaves behind are copies of the same secrets.
void restrict_state_files(const Config& cfg) {
    for (const std::string& path : {cfg.identity_path(), cfg.contacts_path(), cfg.channels_path(),
                                    cfg.messages_path(), cfg.settings_path()}) {
        for (const char* suffix : {"", ".bak", ".tmp"}) restrict_to_owner(path + suffix);
    }
}

bool exists(const std::string& path) {
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0;
}

// What MeshCore's companion calls a node nobody has named: the first four
// bytes of its key, in the upper-case hex Utils::toHex writes.
std::string default_name(ByteView pub) {
    std::string name = hex(subview(pub, 0, 4));
    for (char& c : name) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return name;
}

}  // namespace

// The directory is not created here. systemd's StateDirectory= makes it for the
// service; anywhere else, a path that is not there is far more likely a typo
// than a first run, and creating it would quietly start a new node.
bool App::check_state_dir() {
    struct stat st {};
    if (::stat(cfg_.state_dir.c_str(), &st) != 0) {
        LOG_ERROR("state directory %s: %s — create it, owned by the daemon's user and mode 0700",
                  cfg_.state_dir.c_str(), std::strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        LOG_ERROR("state directory %s is not a directory", cfg_.state_dir.c_str());
        return false;
    }
    // Said rather than fixed: narrowing a directory is the operator's call. The
    // files in it are restricted regardless, so what shows is their names, sizes
    // and times rather than their contents.
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        LOG_WARN("state directory %s is open to other users (mode %04o); chmod 700 it",
                 cfg_.state_dir.c_str(), static_cast<unsigned>(st.st_mode & 07777));
    }
    return true;
}

bool App::load_or_create_identity() {
    std::string error;
    if (auto id = crypto::LocalIdentity::load(cfg_.identity_path(), error)) {
        identity_ = std::make_unique<crypto::LocalIdentity>(*id);
        LOG_INFO("identity: loaded %s from %s", hex_prefix(identity_->pub()).c_str(),
                 cfg_.identity_path().c_str());
        return true;
    }
    if (!error.empty()) {
        LOG_ERROR("identity: %s — refusing to replace the existing node key", error.c_str());
        return false;
    }

    // No key, but a node has lived here: the key was lost — a partial restore,
    // a stray rm — rather than never made. Minting one would start a stranger
    // on top of that node's contacts and channels, and every peer that knew it
    // would be left holding a contact that never speaks again. The settings
    // are not evidence of that: nothing in them is bound to the key, and an
    // operator without an app writes them before the first start.
    for (const std::string& path :
         {cfg_.contacts_path(), cfg_.channels_path(), cfg_.messages_path()}) {
        if (!exists(path)) continue;
        LOG_ERROR("identity: %s is missing but %s is not — restore the identity from a backup, "
                  "or move the rest of %s aside to start a new node on purpose",
                  cfg_.identity_path().c_str(), path.c_str(), cfg_.state_dir.c_str());
        return false;
    }

    // No key and nothing else: this is a first run.
    identity_ = std::make_unique<crypto::LocalIdentity>(crypto::LocalIdentity::generate());
    if (!identity_->save(cfg_.identity_path())) {
        LOG_ERROR("identity: generated a new key but could not save it — refusing to start "
                  "with an identity that would change on restart");
        return false;
    }
    LOG_INFO("identity: generated new node %s, saved to %s", hex(identity_->pub()).c_str(),
             cfg_.identity_path().c_str());
    return true;
}

std::unique_ptr<radio::Radio> App::make_radio(std::string& error) {
#if CORELETD_HAVE_SX1262
    radio::Sx1262::Pins pins;
    pins.spidev = cfg_.spi.spidev;
    pins.gpiochip = cfg_.spi.gpiochip;
    pins.irq = cfg_.spi.irq_pin;
    pins.busy = cfg_.spi.busy_pin;
    pins.reset = cfg_.spi.reset_pin;
    pins.nss = cfg_.spi.nss_pin;
    pins.rxen = cfg_.spi.rxen_pin;
    pins.txen = cfg_.spi.txen_pin;
    pins.spi_speed_hz = cfg_.spi.spi_speed_hz;
    return std::make_unique<radio::Sx1262>(cfg_.radio, pins, cfg_.spi.retry_interval_s * 1000);
#else
    error = "this build has no radio backend (built with CORELETD_RADIO_SX1262=OFF)";
    return nullptr;
#endif
}

bool App::start() {
    if (!crypto::init()) return false;
    if (!check_state_dir()) return false;
    restrict_state_files(cfg_);
    // First, since the default name is the key's. A first run whose settings
    // are refused below keeps the key it minted, which is the node's either
    // way.
    if (!load_or_create_identity()) return false;
    if (cfg_.node.name.empty()) cfg_.node.name = default_name(identity_->pub());

    // Before anything is built from the config, since the settings choose the
    // radio's parameters and the node's name.
    settings_ = std::make_unique<SettingsStore>(cfg_);
    std::string error;
    if (!settings_->load(error)) {
        LOG_ERROR("settings: %s — correct it, or remove the line to take the default",
                  error.c_str());
        return false;
    }

    contacts_ = std::make_unique<mesh::ContactStore>(*identity_, cfg_.contacts_path());
    if (load_state(*contacts_, cfg_.contacts_path(), "contacts") == mesh::LoadResult::Missing)
        LOG_INFO("contacts: starting with an empty store");

    channels_ = std::make_unique<mesh::ChannelStore>(cfg_.channels_path());
    if (load_state(*channels_, cfg_.channels_path(), "channels") == mesh::LoadResult::Missing)
        LOG_INFO("channels: using defaults (slot 0 = Public)");

    // Non-null already only when one was handed to the constructor; otherwise
    // construct the production backend compiled into this build. A radio
    // handed in was built before the settings file was read.
    if (!radio_)
        radio_ = make_radio(error);
    else
        radio_->reconfigure(cfg_.radio);
    if (!radio_) {
        LOG_ERROR("radio: %s", error.c_str());
        return false;
    }

    dispatcher_ = std::make_unique<mesh::Dispatcher>(loop_, *radio_);
    if (!dispatcher_->start(error)) {
        LOG_ERROR("radio: %s", error.c_str());
        return false;
    }

    node_ = std::make_unique<mesh::Node>(loop_, *dispatcher_, *identity_, *contacts_, *channels_,
                                         cfg_.node);
    node_->start();
    settings_->attach(*node_, *dispatcher_);

    if (load_state(node_->inbox(), cfg_.messages_path(), "messages") ==
        mesh::LoadResult::Loaded) {
        LOG_INFO("messages: recovered %zu waiting for an app", node_->inbox().size());
    }

    state_ = std::make_unique<mesh::StateWriter>(loop_, *contacts_, *channels_,
                                                 node_->inbox());
    state_->start();

    server_ = std::make_unique<companion::Server>(loop_, cfg_.companion);
    if (!server_->start(error)) {
        LOG_ERROR("companion: %s", error.c_str());
        return false;
    }

    companion::DeviceMetrics::Info info;
    info.model = "uConsole AIO v2";
    info.firmware_build = CORELETD_VERSION;
    info.version = CORELETD_VERSION;
    info.max_contacts_div2 = mesh::ContactStore::kMaxContacts / 2;
    info.max_channels = mesh::ChannelStore::kMaxChannels;
    metrics_ = std::make_unique<HostMetrics>(std::move(info), cfg_.state_dir);

    session_ = std::make_unique<companion::Session>(loop_.clock(), *server_, *node_, *contacts_,
                                                    *channels_, *radio_, *state_, *metrics_,
                                                    *settings_);
    session_->attach();

    log_status();
    return true;
}

void App::log_status() {
    LOG_INFO("coreletd %s ready", CORELETD_VERSION);
    LOG_INFO("  node      : %s \"%s\"", hex_prefix(identity_->pub()).c_str(),
             cfg_.node.name.c_str());
    LOG_INFO("  radio     : %s", radio_->describe().c_str());
    if (!cfg_.radio.has_frequency()) {
        LOG_WARN("no frequency set — nothing is transmitted until a companion app sets the "
                 "radio parameters");
    }
    if (cfg_.companion.transport == companion::Server::Transport::Unix)
        LOG_INFO("  companion : unix://%s", cfg_.companion.socket_path.c_str());
    else
        LOG_INFO("  companion : tcp://%s:%u", cfg_.companion.bind_addr.c_str(),
                 cfg_.companion.port);
    LOG_INFO("  state     : %s", cfg_.state_dir.c_str());
    LOG_INFO("  contacts  : %zu", contacts_->size());

    if (!clock_is_valid()) {
        LOG_WARN("system clock looks unset — adverts are suppressed until the app sets the "
                 "time or the RTC is configured");
    }
}

void App::run() { loop_.run(); }

void App::request_stop() {
    LOG_INFO("shutting down");
    if (state_) state_->flush();
    if (server_) server_->shutdown();
    if (radio_) radio_->shutdown();
    loop_.stop();
}

}  // namespace clt
