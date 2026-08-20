#include "mesh/state_writer.h"

namespace clt::mesh {

StateWriter::StateWriter(EventLoop& loop, ContactStore& contacts, ChannelStore& channels,
                         MessageInbox& inbox, uint32_t coalesce_ms)
    : loop_(loop),
      contacts_(contacts),
      channels_(channels),
      inbox_(inbox),
      coalesce_ms_(coalesce_ms) {}

void StateWriter::start() {
    if (sweep_) return;
    sweep_ = loop_.add_repeating(kSweepMs, [this] { flush(); });
}

void StateWriter::request_save() {
    if (pending_) return;
    pending_ = loop_.add_timer(coalesce_ms_, [this] {
        // Drop the handle first: this one has fired, and the flush below can
        // reach code that asks for another save.
        pending_.reset();
        flush();
    });
}

bool StateWriter::flush() {
    bool ok = true;
    // A failed save leaves its store dirty, so the next attempt retries it.
    if (contacts_.dirty()) ok = contacts_.save() && ok;
    if (channels_.dirty()) ok = channels_.save() && ok;
    if (inbox_.dirty()) ok = inbox_.save() && ok;
    healthy_ = ok;
    return ok;
}

}  // namespace clt::mesh
