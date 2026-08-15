#pragma once

#include <cstdint>

namespace clt {

// Monotonic milliseconds since daemon start. Used for timers, retries and
// duty-cycle accounting — never for anything that goes on the wire.
uint32_t millis();

// The source of monotonic milliseconds for everything that measures elapsed
// time: the event loop's timers, the dispatcher's queue expiry and dedup
// window, and the duty-cycle accounting.
//
// The daemon runs on millis(). Tests substitute a clock they drive, which is
// what makes the 8/16/32 s retry ladder and the one-hour duty-cycle window
// observable at all — nobody writes a 56-second unit test.
class Clock {
public:
    virtual ~Clock() = default;
    virtual uint32_t now_ms() const = 0;

    // Virtual time does not pass on its own: rather than sleeping, EventLoop
    // moves it straight to whatever is due next. A real clock reports false
    // and is waited on with poll(), and ignores set_now_ms().
    virtual bool is_virtual() const { return false; }
    virtual void set_now_ms(uint32_t /*ms*/) {}
};

// The clock every EventLoop uses unless handed another one.
Clock& millis_clock();

// Time only moves when something moves it. This lives beside the interface
// rather than in the tests because EventLoop is what drives it, through
// Clock::set_now_ms() — `loop.advance(8000)` is the point of the whole seam.
class ManualClock final : public Clock {
public:
    explicit ManualClock(uint32_t start_ms = 0) : now_ms_(start_ms) {}

    uint32_t now_ms() const override { return now_ms_; }
    bool is_virtual() const override { return true; }
    void set_now_ms(uint32_t ms) override { now_ms_ = ms; }

    // Moves time without dispatching anything. Use EventLoop::advance() for
    // anything holding timers; this is for testing a component that only reads
    // the clock, such as DutyCycle.
    void advance(uint32_t ms) { now_ms_ += ms; }

private:
    uint32_t now_ms_ = 0;
};

// Wall-clock unix seconds. This is what goes into adverts and message
// timestamps, so it must be sane: MeshCore peers reject adverts whose timestamp
// is older than the one they already hold for that key.
uint32_t unix_now();

// The companion app pushes device time via CMD_SET_DEVICE_TIME. We do not step
// the system clock (the daemon is not privileged); we keep an offset instead.
void set_clock_offset(int64_t seconds);
int64_t clock_offset();

// True once we believe the wall clock is trustworthy — either the RTC/NTP gave
// us a plausible time at boot, or the app set it.
bool clock_is_valid();

}  // namespace clt
