#include "mesh/inbox.h"

#include "util/log.h"

namespace clt::mesh {

void MessageInbox::store(StoredMessage msg) {
    messages_.push_back(std::move(msg));
    while (messages_.size() > limit_) {
        LOG_WARN("message queue full, dropping oldest");
        messages_.pop_front();
    }
}

std::optional<StoredMessage> MessageInbox::pop() {
    if (messages_.empty()) return std::nullopt;
    StoredMessage m = std::move(messages_.front());
    messages_.pop_front();
    return m;
}

}  // namespace clt::mesh
