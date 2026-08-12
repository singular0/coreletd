#pragma once

#include <cstdint>

namespace umc {

// Monotonic milliseconds since daemon start. Used for timers, retries and
// duty-cycle accounting — never for anything that goes on the wire.
uint32_t millis();

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

}  // namespace umc
