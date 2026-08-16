#pragma once

#include <memory>
#include <string>

#include "companion/server.h"
#include "companion/session.h"
#include "daemon/config.h"
#include "daemon/eventloop.h"
#include "daemon/host_metrics.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/node.h"
#include "mesh/state_writer.h"
#include "radio/radio.h"
#include "util/clock.h"

namespace clt {

// Owns every subsystem and wires them together. Construction order matters:
// identity, then radio, then dispatcher, then node, then the state writer, then
// the companion server.
class App {
public:
    // The radio and the clock are the two things the daemon builds for itself
    // and a test replaces. A null radio means the daemon constructs its
    // compiled-in backend; handing one in stands the whole stack up against a
    // radio the test drives. The clock reaches every subsystem through the
    // loop, so a ManualClock runs all of it on virtual time.
    explicit App(Config cfg, std::unique_ptr<radio::Radio> radio = nullptr,
                 Clock& clock = millis_clock());
    ~App();

    // Returns false with the reason logged if anything fails to come up.
    bool start();
    void run();
    void request_stop();

    // The loop everything is scheduled on: main() hangs its signal check here,
    // and a harness steps virtual time through it.
    EventLoop& loop() { return loop_; }

private:
    bool load_or_create_identity();
    bool ensure_state_dir();
    std::unique_ptr<radio::Radio> make_radio(std::string& error);
    void log_status();

    Config cfg_;
    // Declared before every subsystem, and so destroyed after all of them.
    // Subsystems hold EventLoop registration handles that deregister on
    // destruction, which they can only do while the loop is still alive.
    EventLoop loop_;

    std::unique_ptr<crypto::LocalIdentity> identity_;
    std::unique_ptr<radio::Radio> radio_;
    std::unique_ptr<mesh::ContactStore> contacts_;
    std::unique_ptr<mesh::ChannelStore> channels_;
    std::unique_ptr<mesh::Dispatcher> dispatcher_;
    std::unique_ptr<mesh::Node> node_;
    std::unique_ptr<mesh::StateWriter> state_;
    std::unique_ptr<HostMetrics> metrics_;
    std::unique_ptr<companion::Server> server_;
    std::unique_ptr<companion::Session> session_;
};

}  // namespace clt
