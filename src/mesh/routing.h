#pragma once

#include "mesh/contacts.h"
#include "mesh/dispatcher.h"

namespace clt::mesh {

// Queues `p` for a contact: along its known return path when we have one, by
// flooding otherwise. `force_flood` ignores a known path, which the last send
// attempt uses. Returns false without queueing when the packet cannot be
// represented on the wire — callers reporting success must check.
inline bool route_to(Dispatcher& dispatcher, proto::Packet& p, const Contact& to,
                     uint8_t priority, bool force_flood = false,
                     Dispatcher::TxResultHandler on_result = {}) {
    if (to.path_known && !force_flood) {
        p.route = proto::RouteType::Direct;
        p.path = to.out_path;
        p.path_hash_size = 1;
    } else {
        p.route = proto::RouteType::Flood;
        p.path.clear();
    }
    return dispatcher.send(std::move(p), priority, 0, std::move(on_result));
}

}  // namespace clt::mesh
