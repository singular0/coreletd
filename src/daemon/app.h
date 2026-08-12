#pragma once

#include <functional>
#include <memory>
#include <string>

#include "companion/server.h"
#include "companion/session.h"
#include "daemon/config.h"
#include "daemon/eventloop.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/node.h"
#include "radio/radio.h"

namespace umc {

// Owns every subsystem and wires them together. Construction order matters:
// identity, then radio, then dispatcher, then node, then companion server.
class App {
public:
    explicit App(Config cfg);
    ~App();

    // Returns false with the reason logged if anything fails to come up.
    bool start();
    void run();
    void request_stop();
    // Forwarded to the event loop so a signal handler can break out of poll().
    void set_interrupt_check(std::function<bool()> fn) {
        loop_.set_interrupt_check(std::move(fn));
    }

private:
    bool load_or_create_identity();
    bool ensure_state_dir();
    std::unique_ptr<radio::Radio> make_radio(std::string& error);
    void log_status();

    Config cfg_;
    EventLoop loop_;

    std::unique_ptr<crypto::LocalIdentity> identity_;
    std::unique_ptr<radio::Radio> radio_;
    std::unique_ptr<mesh::ContactStore> contacts_;
    std::unique_ptr<mesh::ChannelStore> channels_;
    std::unique_ptr<mesh::Dispatcher> dispatcher_;
    std::unique_ptr<mesh::Node> node_;
    std::unique_ptr<companion::Server> server_;
    std::unique_ptr<companion::Session> session_;
};

}  // namespace umc
