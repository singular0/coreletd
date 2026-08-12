#include "util/clock.h"

#include <chrono>

namespace umc {

namespace {
const std::chrono::steady_clock::time_point g_start = std::chrono::steady_clock::now();
int64_t g_offset = 0;
bool g_valid = false;

// Anything before 2024-01-01 means the RTC is dead or was never set.
constexpr uint32_t kPlausibleEpoch = 1704067200;
}  // namespace

uint32_t millis() {
    using namespace std::chrono;
    return static_cast<uint32_t>(
        duration_cast<milliseconds>(steady_clock::now() - g_start).count());
}

uint32_t unix_now() {
    using namespace std::chrono;
    int64_t t = duration_cast<seconds>(system_clock::now().time_since_epoch()).count() + g_offset;
    if (t < 0) t = 0;
    return static_cast<uint32_t>(t);
}

void set_clock_offset(int64_t seconds) {
    g_offset = seconds;
    g_valid = true;
}

int64_t clock_offset() { return g_offset; }

bool clock_is_valid() { return g_valid || unix_now() >= kPlausibleEpoch; }

}  // namespace umc
