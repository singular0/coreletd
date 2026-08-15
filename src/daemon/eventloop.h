#pragma once

#include <poll.h>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <utility>

#include "util/clock.h"

namespace clt {

// Single-threaded poll() loop. poll() rather than epoll/kqueue so the same code
// runs on the uConsole and on a dev machine; the fd count here is tiny (radio
// IRQ, listening socket, one client) so the O(n) scan costs nothing.
//
// Everything in the daemon runs on this one thread: there is no locking
// anywhere else in the codebase, and callbacks must not block.
class EventLoop {
public:
    // The loop owns the clock. Everything scheduled already goes through it,
    // so everything that measures elapsed time reads the time from it too
    // rather than from the global millis(). Hand it a ManualClock and the
    // subsystems built on top run on virtual time without knowing it.
    explicit EventLoop(Clock& clock = millis_clock()) : clock_(clock) {}

    using FdCallback = std::function<void(short revents)>;
    using TimerCallback = std::function<void()>;

    enum class Kind { Fd, Timer };

    // Owns one registration and deregisters when destroyed.
    //
    // Callbacks capture `this`, so the object that registers holds the handle
    // as a member: the registration then cannot outlive what its callback
    // captured, whatever order the owner's members happen to be destroyed in,
    // and no destructor has to remember to cancel anything.
    //
    // Move-only. A default-constructed or moved-from handle is inert. The
    // handle does not keep the loop alive and must not outlive it, so anything
    // owning both declares the loop first — see `daemon/app.h`.
    template <Kind K>
    class Registration {
    public:
        Registration() = default;
        ~Registration() { reset(); }

        Registration(Registration&& other) noexcept
            : loop_(std::exchange(other.loop_, nullptr)),
              id_(std::exchange(other.id_, 0)) {}
        Registration& operator=(Registration&& other) noexcept {
            if (this != &other) {
                reset();
                loop_ = std::exchange(other.loop_, nullptr);
                id_ = std::exchange(other.id_, 0);
            }
            return *this;
        }

        Registration(const Registration&) = delete;
        Registration& operator=(const Registration&) = delete;

        // Whether a registration is held, which is not the same as whether it
        // is still pending: a one-shot timer that has already run still reads
        // as true. Callbacks that track being armed reset the handle
        // themselves, and doing so from inside the callback is fine.
        explicit operator bool() const { return loop_ != nullptr; }

        // Deregisters ahead of destruction. Cancelling something that has
        // already fired is a no-op rather than a mistake — the loop hands out
        // ids from a counter and never reuses one, so a stale id can only ever
        // match the registration it came from.
        void reset() {
            if (!loop_) return;
            EventLoop* loop = std::exchange(loop_, nullptr);
            if constexpr (K == Kind::Fd) {
                loop->remove_fd(id_);
            } else {
                loop->cancel_timer(id_);
            }
        }

    private:
        friend class EventLoop;
        Registration(EventLoop& loop, uint64_t id) : loop_(&loop), id_(id) {}

        EventLoop* loop_ = nullptr;
        uint64_t id_ = 0;
    };

    using FdWatch = Registration<Kind::Fd>;
    using Timer = Registration<Kind::Timer>;

    // The fd is not owned. Drop the watch before closing the fd, or poll() will
    // be handed a descriptor that may already have been reused.
    [[nodiscard]] FdWatch add_fd(int fd, short events, FdCallback cb);
    void update_fd(const FdWatch& watch, short events);

    [[nodiscard]] Timer add_timer(uint32_t delay_ms, TimerCallback cb);
    [[nodiscard]] Timer add_repeating(uint32_t interval_ms, TimerCallback cb);

    // Monotonic milliseconds, from whichever clock this loop was given. The
    // subsystems the loop drives use this rather than millis() directly, so a
    // test can move them all together.
    uint32_t now_ms() const { return clock_.now_ms(); }

    // For handing on to something that reads the clock but schedules nothing,
    // such as DutyCycle.
    Clock& clock() const { return clock_; }

    // Lets `ms` of virtual time pass, dispatching timers in due order as it
    // goes, and returns without ever entering poll() or sleeping. This is what
    // makes the retry ladder and the duty-cycle window testable: advance(8000)
    // rather than a real eight seconds.
    //
    // Stops early if a callback calls stop(). Does nothing on a real clock,
    // where time is not ours to move.
    void advance(uint32_t ms);

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
    using WatchId = uint64_t;
    using TimerId = uint64_t;

    struct WatchEntry {
        int fd = -1;
        short events = 0;
        FdCallback cb;
        bool dead = false;
    };
    struct TimerEntry {
        uint32_t due_ms = 0;
        uint32_t interval_ms = 0;  // 0 == one-shot
        TimerCallback cb;
        bool dead = false;
    };

    // Only reachable through a Registration, which is what keeps an id from
    // outliving the handle that owns it.
    void remove_fd(WatchId id);
    void cancel_timer(TimerId id);

    // Milliseconds until the soonest live timer, negative when one is already
    // overdue, nullopt when none is armed.
    std::optional<int64_t> next_due_ms() const;
    int next_timeout_ms() const;
    void run_due_timers();
    void reap();

    Clock& clock_;
    std::function<bool()> interrupt_check_;
    std::map<WatchId, WatchEntry> watches_;
    std::map<TimerId, TimerEntry> timers_;
    WatchId next_watch_ = 1;
    TimerId next_timer_ = 1;
    bool stop_ = false;
    bool dirty_ = false;  // a watch or timer was removed mid-dispatch
};

}  // namespace clt
