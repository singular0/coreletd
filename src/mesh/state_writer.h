#pragma once

#include <cstdint>

#include "daemon/eventloop.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"

namespace umc::mesh {

// Decides when persisted state is written. The stores own their files and
// track their own dirty flags; this owns the timing, so nothing else has to
// choose between writing on every change and hoping something else does it.
//
// Writes are coalesced. An app syncing forty contacts sends forty commands,
// and each durable replacement costs a full rewrite plus two fsyncs; batching
// them makes that one write. The cost is that a mutating command is answered
// before its bytes are on disk — see `healthy()`.
class StateWriter {
public:
    // Long enough to absorb an app working through its contact list one
    // command at a time, short enough to keep the window of loss small.
    static constexpr uint32_t kCoalesceMs = 1000;
    // Backstop for state that changes without anyone asking for a save: the
    // receive path updates last_seen for every packet it decrypts.
    static constexpr uint32_t kSweepMs = 60000;

    StateWriter(EventLoop& loop, ContactStore& contacts, ChannelStore& channels,
                uint32_t coalesce_ms = kCoalesceMs);
    ~StateWriter();

    // Arms the periodic sweep. Nothing is written before this is called.
    void start();

    // Writes every dirty store after a short delay. Further requests before
    // that delay elapses join the pending write rather than adding one.
    void request_save();

    // Writes now, and reports whether everything that needed writing got
    // written. The daemon calls this on the way out.
    bool flush();

    // False when the last write failed — for the companion protocol, the
    // difference between "accepted" and "accepted but not persisted". Because
    // writes are deferred this describes the previous attempt, so a newly
    // unwritable state directory is reported one save late rather than never.
    bool healthy() const { return healthy_; }

private:
    EventLoop& loop_;
    ContactStore& contacts_;
    ChannelStore& channels_;
    uint32_t coalesce_ms_;

    // 0 == not armed; the loop hands out ids from 1.
    EventLoop::TimerId sweep_ = 0;
    EventLoop::TimerId pending_ = 0;
    bool healthy_ = true;
};

}  // namespace umc::mesh
