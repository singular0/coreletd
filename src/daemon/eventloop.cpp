#include "daemon/eventloop.h"

#include <errno.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

#include "util/clock.h"
#include "util/log.h"

namespace umc {

EventLoop::FdWatch EventLoop::add_fd(int fd, short events, FdCallback cb) {
    WatchId id = next_watch_++;
    watches_[id] = WatchEntry {fd, events, std::move(cb), false};
    return FdWatch(*this, id);
}

void EventLoop::update_fd(const FdWatch& watch, short events) {
    auto it = watches_.find(watch.id_);
    if (it != watches_.end()) it->second.events = events;
}

void EventLoop::remove_fd(WatchId id) {
    auto it = watches_.find(id);
    if (it == watches_.end()) return;
    // Tombstone rather than erase: we may be inside the dispatch loop holding
    // an iterator into this map.
    it->second.dead = true;
    dirty_ = true;
}

EventLoop::Timer EventLoop::add_timer(uint32_t delay_ms, TimerCallback cb) {
    TimerId id = next_timer_++;
    timers_[id] = TimerEntry {millis() + delay_ms, 0, std::move(cb), false};
    return Timer(*this, id);
}

EventLoop::Timer EventLoop::add_repeating(uint32_t interval_ms, TimerCallback cb) {
    if (interval_ms == 0) interval_ms = 1;
    TimerId id = next_timer_++;
    timers_[id] = TimerEntry {millis() + interval_ms, interval_ms, std::move(cb), false};
    return Timer(*this, id);
}

void EventLoop::cancel_timer(TimerId id) {
    auto it = timers_.find(id);
    if (it == timers_.end()) return;
    it->second.dead = true;
    dirty_ = true;
}

int EventLoop::next_timeout_ms() const {
    uint32_t now = millis();
    int64_t soonest = std::numeric_limits<int64_t>::max();
    for (const auto& [id, t] : timers_) {
        if (t.dead) continue;
        // Unsigned subtraction handles the 49-day millis() wrap correctly.
        int64_t remaining = static_cast<int32_t>(t.due_ms - now);
        soonest = std::min(soonest, remaining);
    }
    if (soonest == std::numeric_limits<int64_t>::max()) return -1;  // block
    if (soonest < 0) return 0;
    return static_cast<int>(std::min<int64_t>(soonest, 60000));
}

void EventLoop::run_due_timers() {
    uint32_t now = millis();

    // Snapshot ids: a callback may add or cancel timers.
    std::vector<TimerId> due;
    for (const auto& [id, t] : timers_) {
        if (t.dead) continue;
        if (static_cast<int32_t>(t.due_ms - now) <= 0) due.push_back(id);
    }

    for (TimerId id : due) {
        auto it = timers_.find(id);
        if (it == timers_.end() || it->second.dead) continue;

        if (it->second.interval_ms > 0) {
            // Reschedule before running so a callback can cancel itself.
            it->second.due_ms = now + it->second.interval_ms;
            TimerCallback cb = it->second.cb;
            cb();
        } else {
            TimerCallback cb = it->second.cb;
            it->second.dead = true;
            dirty_ = true;
            cb();
        }
    }
}

void EventLoop::reap() {
    if (!dirty_) return;
    for (auto it = watches_.begin(); it != watches_.end();)
        it = it->second.dead ? watches_.erase(it) : std::next(it);
    for (auto it = timers_.begin(); it != timers_.end();)
        it = it->second.dead ? timers_.erase(it) : std::next(it);
    dirty_ = false;
}

void EventLoop::run() {
    stop_ = false;
    while (!stop_) {
        // A signal may have arrived between iterations, not just inside poll().
        if (interrupt_check_ && interrupt_check_()) break;

        reap();

        std::vector<pollfd> pfds;
        std::vector<WatchId> ids;
        pfds.reserve(watches_.size());
        ids.reserve(watches_.size());
        for (const auto& [id, w] : watches_) {
            if (w.dead || w.fd < 0) continue;
            pfds.push_back(pollfd {w.fd, w.events, 0});
            ids.push_back(id);
        }

        int timeout = next_timeout_ms();
        if (pfds.empty() && timeout < 0) {
            LOG_WARN("event loop has nothing to wait on, stopping");
            break;
        }

        int n = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeout);
        if (n < 0) {
            // A signal arrived. Give the interrupt check a chance to stop us
            // before going back to sleep, or SIGTERM would never be noticed.
            if (errno == EINTR) {
                if (interrupt_check_ && interrupt_check_()) break;
                continue;
            }
            LOG_ERROR("poll failed: %s", strerror(errno));
            break;
        }

        for (size_t i = 0; i < pfds.size() && n > 0; i++) {
            if (pfds[i].revents == 0) continue;
            n--;
            auto it = watches_.find(ids[i]);
            // The watch may have been removed by an earlier callback in this
            // same pass.
            if (it == watches_.end() || it->second.dead) continue;
            it->second.cb(pfds[i].revents);
            if (stop_) break;
        }

        if (!stop_) run_due_timers();
    }
}

void EventLoop::stop() { stop_ = true; }

}  // namespace umc
