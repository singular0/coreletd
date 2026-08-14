#pragma once

#include <cstdint>
#include <string>

namespace clt::companion {

// What the app can ask about the machine we run on.
//
// The protocol layer needs these numbers but has no business knowing where they
// come from: a battery lives behind a sysfs walk on Linux and nowhere at all on
// a dev machine, and disk usage is a syscall against a path only the daemon
// knows. Session takes this interface; the daemon supplies the implementation.
class DeviceMetrics {
public:
    virtual ~DeviceMetrics() = default;

    // Fixed for the life of the process: what CMD_DEVICE_QUERY answers.
    struct Info {
        std::string model;
        std::string firmware_build;
        std::string version;
        // The protocol sends the contact limit halved, in one byte.
        uint8_t max_contacts_div2 = 0;
        uint8_t max_channels = 0;
    };
    virtual const Info& info() const = 0;

    // Battery voltage in millivolts. 0 means "no battery, or unreadable", which
    // the app renders as unknown rather than as a flat pack.
    virtual uint16_t battery_mv() const = 0;

    // Space on the filesystem holding the state directory. Both zero when it
    // cannot be determined, which is again the app's "unknown".
    struct Storage {
        uint64_t used_bytes = 0;
        uint64_t total_bytes = 0;
    };
    virtual Storage storage() const = 0;
};

}  // namespace clt::companion
