#include <poll.h>
#include <unistd.h>

#include <memory>

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

int main() {
    test_dropped_handle_never_fires();
    test_registration_dies_with_its_owner();
    test_assigning_over_a_handle_cancels_the_old_one();
    test_repeating_timer_can_cancel_itself();
    test_fd_watch_deregisters();
    return finish("eventloop");
}
