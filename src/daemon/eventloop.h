#pragma once

#include <poll.h>

#include <cstdint>
#include <functional>
#include <map>
#include <vector>

namespace umc {

// Single-threaded poll() loop. poll() rather than epoll/kqueue so the same code
// runs on the uConsole and on a dev machine; the fd count here is tiny (radio
// IRQ, listening socket, one client) so the O(n) scan costs nothing.
//
// Everything in the daemon runs on this one thread: there is no locking
// anywhere else in the codebase, and callbacks must not block.
class EventLoop {
public:
    using FdCallback = std::function<void(short revents)>;
    using TimerCallback = std::function<void()>;

    using WatchId = uint64_t;
    using TimerId = uint64_t;

    // The fd is not owned; the caller closes it after removing the watch.
    WatchId add_fd(int fd, short events, FdCallback cb);
    void update_fd(WatchId id, short events);
    void remove_fd(WatchId id);

    TimerId add_timer(uint32_t delay_ms, TimerCallback cb);
    TimerId add_repeating(uint32_t interval_ms, TimerCallback cb);
    void cancel_timer(TimerId id);

    // Polled at the top of every iteration and after poll() is interrupted.
    // Returning true stops the loop. This is how a signal handler gets us out
    // of poll(): delivering the signal makes poll() fail with EINTR, and the
    // handler itself only has to set a sig_atomic_t flag.
    void set_interrupt_check(std::function<bool()> fn) { interrupt_check_ = std::move(fn); }

    // Runs until stop(). Safe to add/remove watches and timers from callbacks.
    void run();
    void stop();
    bool stopping() const { return stop_; }

private:
    struct Watch {
        int fd = -1;
        short events = 0;
        FdCallback cb;
        bool dead = false;
    };
    struct Timer {
        uint32_t due_ms = 0;
        uint32_t interval_ms = 0;  // 0 == one-shot
        TimerCallback cb;
        bool dead = false;
    };

    int next_timeout_ms() const;
    void run_due_timers();
    void reap();

    std::function<bool()> interrupt_check_;
    std::map<WatchId, Watch> watches_;
    std::map<TimerId, Timer> timers_;
    WatchId next_watch_ = 1;
    TimerId next_timer_ = 1;
    bool stop_ = false;
    bool dirty_ = false;  // a watch or timer was removed mid-dispatch
};

}  // namespace umc
