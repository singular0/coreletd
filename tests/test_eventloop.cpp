#include <poll.h>
#include <unistd.h>

#include <memory>
#include <vector>

#include "daemon/eventloop.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;

namespace {

// The shape every subsystem has: a repeating callback reaching back into the
// object that registered it. Holding the handle here is what stops the loop
// from calling into a destroyed Ticker.
struct Ticker {
    Ticker(EventLoop& loop, int& ticks) : ticks_(ticks) {
        timer_ = loop.add_repeating(1, [this] { ticks_++; });
    }

    int& ticks_;
    EventLoop::Timer timer_;
};

}  // namespace

static void test_dropped_handle_never_fires() {
    EventLoop loop;
    int fired = 0;
    {
        auto scoped = loop.add_timer(1, [&fired] { fired++; });
    }

    auto deadline = loop.add_timer(20, [&loop] { loop.stop(); });
    loop.run();

    CHECK_EQ(fired, 0);
}

static void test_registration_dies_with_its_owner() {
    EventLoop loop;
    int ticks = 0;
    auto ticker = std::make_unique<Ticker>(loop, ticks);

    int ticks_at_destruction = 0;
    auto drop = loop.add_timer(20, [&] {
        ticks_at_destruction = ticks;
        ticker.reset();
    });
    auto deadline = loop.add_timer(50, [&loop] { loop.stop(); });
    loop.run();

    // It was genuinely running, and then it stopped — without Ticker having a
    // destructor that remembers to cancel anything.
    CHECK(ticks_at_destruction > 0);
    CHECK_EQ(ticks, ticks_at_destruction);
}

static void test_assigning_over_a_handle_cancels_the_old_one() {
    // How the dispatcher replaces a pending pump and the sender re-arms a
    // retry: assign the new registration over the old handle, nothing else.
    EventLoop loop;
    int first = 0;
    int second = 0;

    EventLoop::Timer timer = loop.add_timer(5, [&first] { first++; });
    timer = loop.add_timer(5, [&second] { second++; });

    auto deadline = loop.add_timer(30, [&loop] { loop.stop(); });
    loop.run();

    CHECK_EQ(first, 0);
    CHECK_EQ(second, 1);
}

static void test_repeating_timer_can_cancel_itself() {
    EventLoop loop;
    EventLoop::Timer timer;
    int fired = 0;

    timer = loop.add_repeating(1, [&] {
        fired++;
        timer.reset();
    });

    auto deadline = loop.add_timer(20, [&loop] { loop.stop(); });
    loop.run();

    CHECK_EQ(fired, 1);
    CHECK(!timer);
}

static void test_fd_watch_deregisters() {
    int fds[2] = {-1, -1};
    if (::pipe(fds) != 0) {
        CHECK(false);
        return;
    }

    EventLoop loop;
    int reads = 0;
    auto drain = [&] {
        char c = 0;
        ssize_t n = ::read(fds[0], &c, 1);
        (void)n;
        reads++;
    };

    {
        auto watch = loop.add_fd(fds[0], POLLIN, [&](short) { drain(); });
        ssize_t n = ::write(fds[1], "x", 1);
        (void)n;

        auto deadline = loop.add_timer(20, [&loop] { loop.stop(); });
        loop.run();
        CHECK_EQ(reads, 1);
    }

    // The fd is still open and still readable; with the watch gone it wakes
    // nothing.
    ssize_t n = ::write(fds[1], "y", 1);
    (void)n;
    auto deadline = loop.add_timer(20, [&loop] { loop.stop(); });
    loop.run();
    CHECK_EQ(reads, 1);

    ::close(fds[0]);
    ::close(fds[1]);
}

static void test_advance_dispatches_in_due_order() {
    ManualClock clock;
    EventLoop loop(clock);

    std::vector<int> order;
    auto late = loop.add_timer(32000, [&] { order.push_back(2); });
    auto early = loop.add_timer(8000, [&] { order.push_back(1); });

    loop.advance(7999);
    CHECK_EQ(order.size(), size_t {0});

    loop.advance(1);
    CHECK_EQ(order.size(), size_t {1});
    CHECK_EQ(loop.now_ms(), uint32_t {8000});

    // Advances add up: landing exactly on the requested instant is what lets a
    // test step through a retry ladder one delay at a time.
    loop.advance(24000);
    CHECK_EQ(order.size(), size_t {2});
    CHECK_EQ(order[0], 1);
    CHECK_EQ(order[1], 2);
    CHECK_EQ(loop.now_ms(), uint32_t {32000});
}

static void test_run_does_not_wait_out_virtual_time() {
    // An hour of retries and duty-cycle window, in whatever it costs to
    // dispatch two timers.
    ManualClock clock;
    EventLoop loop(clock);

    int fired = 0;
    auto slow = loop.add_timer(3600000, [&] { fired++; });
    auto deadline = loop.add_timer(3600001, [&loop] { loop.stop(); });

    loop.run();

    CHECK_EQ(fired, 1);
    CHECK_EQ(loop.now_ms(), uint32_t {3600001});
}

static void test_timers_survive_the_millis_wrap() {
    // millis() wraps every 49 days, and the loop's due-time arithmetic is
    // written for it. Start just short of the wrap and step across.
    ManualClock clock(0xFFFFFF00);
    EventLoop loop(clock);

    int before_wrap = 0;
    int after_wrap = 0;
    auto before = loop.add_timer(0x80, [&] { before_wrap++; });
    auto after = loop.add_timer(0x180, [&] { after_wrap++; });

    loop.advance(0x100);
    CHECK_EQ(before_wrap, 1);
    CHECK_EQ(after_wrap, 0);
    CHECK_EQ(loop.now_ms(), uint32_t {0});  // wrapped

    loop.advance(0x100);
    CHECK_EQ(after_wrap, 1);
}

int main() {
    test_dropped_handle_never_fires();
    test_registration_dies_with_its_owner();
    test_assigning_over_a_handle_cancels_the_old_one();
    test_repeating_timer_can_cancel_itself();
    test_fd_watch_deregisters();
    test_advance_dispatches_in_due_order();
    test_run_does_not_wait_out_virtual_time();
    test_timers_survive_the_millis_wrap();
    return finish("eventloop");
}
