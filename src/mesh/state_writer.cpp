#include "mesh/state_writer.h"

namespace umc::mesh {

StateWriter::StateWriter(EventLoop& loop, ContactStore& contacts, ChannelStore& channels,
                         uint32_t coalesce_ms)
    : loop_(loop), contacts_(contacts), channels_(channels), coalesce_ms_(coalesce_ms) {}

StateWriter::~StateWriter() {
    // Both callbacks capture `this`, so they have to go before we do.
    if (sweep_) loop_.cancel_timer(sweep_);
    if (pending_) loop_.cancel_timer(pending_);
}

void StateWriter::start() {
    if (sweep_) return;
    sweep_ = loop_.add_repeating(kSweepMs, [this] { flush(); });
}

void StateWriter::request_save() {
    if (pending_) return;
    pending_ = loop_.add_timer(coalesce_ms_, [this] {
        pending_ = 0;
        flush();
    });
}

bool StateWriter::flush() {
    bool ok = true;
    // A failed save leaves its store dirty, so the next attempt retries it.
    if (contacts_.dirty()) ok = contacts_.save() && ok;
    if (channels_.dirty()) ok = channels_.save() && ok;
    healthy_ = ok;
    return ok;
}

}  // namespace umc::mesh
