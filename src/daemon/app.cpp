#include "daemon/app.h"

#include <filesystem>

#include "crypto/crypto.h"
#include "radio/mock_radio.h"
#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

#if UMESHCORE_HAVE_SX1262
#include "radio/sx1262.h"
#endif

namespace umc {

App::App(Config cfg) : cfg_(std::move(cfg)) {}
App::~App() = default;

bool App::ensure_state_dir() {
    std::error_code ec;
    std::filesystem::create_directories(cfg_.state_dir, ec);
    if (ec) {
        LOG_ERROR("cannot create state directory %s: %s", cfg_.state_dir.c_str(),
                  ec.message().c_str());
        return false;
    }
    return true;
}

bool App::load_or_create_identity() {
    std::string error;
    if (auto id = crypto::LocalIdentity::load(cfg_.identity_path, error)) {
        identity_ = std::make_unique<crypto::LocalIdentity>(*id);
        LOG_INFO("identity: loaded %s from %s", hex_prefix(identity_->pub()).c_str(),
                 cfg_.identity_path.c_str());
        return true;
    }
    if (!error.empty()) {
        LOG_ERROR("identity: %s — refusing to replace the existing node key", error.c_str());
        return false;
    }

    // No key yet: this is a first run.
    identity_ = std::make_unique<crypto::LocalIdentity>(crypto::LocalIdentity::generate());
    if (!identity_->save(cfg_.identity_path)) {
        LOG_ERROR("identity: generated a new key but could not save it — refusing to start "
                  "with an identity that would change on restart");
        return false;
    }
    LOG_INFO("identity: generated new node %s, saved to %s", hex(identity_->pub()).c_str(),
             cfg_.identity_path.c_str());
    return true;
}

std::unique_ptr<radio::Radio> App::make_radio(std::string& error) {
    if (cfg_.use_mock_radio) {
        radio::MockRadio::Options opts;
        opts.replay_file = cfg_.mock_replay_file;
        opts.repeat = true;
        return std::make_unique<radio::MockRadio>(cfg_.radio, std::move(opts));
    }

#if UMESHCORE_HAVE_SX1262
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
    error =
        "this build has no SX1262 backend (built without libgpiod). "
        "Set mock_radio = 1 to run without hardware.";
    return nullptr;
#endif
}

bool App::start() {
    if (!crypto::init()) return false;
    if (!ensure_state_dir()) return false;
    if (!load_or_create_identity()) return false;

    contacts_ = std::make_unique<mesh::ContactStore>(*identity_);
    if (!contacts_->load(cfg_.contacts_path))
        LOG_INFO("contacts: starting with an empty store");

    channels_ = std::make_unique<mesh::ChannelStore>();
    if (!channels_->load(cfg_.channels_path))
        LOG_INFO("channels: using defaults (slot 0 = Public)");

    std::string error;
    radio_ = make_radio(error);
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

    server_ = std::make_unique<companion::Server>(loop_, cfg_.companion);
    if (!server_->start(error)) {
        LOG_ERROR("companion: %s", error.c_str());
        return false;
    }

    companion::Session::DeviceInfo info;
    session_ = std::make_unique<companion::Session>(*server_, *node_, *contacts_, *channels_,
                                                    *radio_, std::move(info));
    session_->set_store_paths(cfg_.contacts_path, cfg_.channels_path);
    session_->attach();

    // Persist stores periodically as a safety net; the session also saves
    // immediately after any companion command that mutates them.
    loop_.add_repeating(60000, [this] {
        if (contacts_->dirty()) contacts_->save(cfg_.contacts_path);
        if (channels_->dirty()) channels_->save(cfg_.channels_path);
    });

    log_status();
    return true;
}

void App::log_status() {
    LOG_INFO("umeshcore %s ready", UMESHCORE_VERSION);
    LOG_INFO("  node      : %s \"%s\"", hex_prefix(identity_->pub()).c_str(),
             cfg_.node.name.c_str());
    LOG_INFO("  radio     : %s", radio_->describe().c_str());
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
    if (contacts_ && contacts_->dirty()) contacts_->save(cfg_.contacts_path);
    if (channels_ && channels_->dirty()) channels_->save(cfg_.channels_path);
    if (server_) server_->shutdown();
    if (radio_) radio_->shutdown();
    loop_.stop();
}

}  // namespace umc
