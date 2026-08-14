#pragma once

#include <string>

#include "companion/device_metrics.h"

namespace clt {

// DeviceMetrics for the machine the daemon is running on.
//
// Discovery happens once, in the constructor: the sysfs battery walk is the
// expensive part and its answer does not change, so a command handler is left
// with one file read. A build with no battery — every non-Linux one, and any
// Linux box without a pack — does no I/O at all.
class HostMetrics final : public companion::DeviceMetrics {
public:
    // `state_dir` selects the filesystem reported by storage().
    HostMetrics(Info info, std::string state_dir);

    const Info& info() const override { return info_; }
    uint16_t battery_mv() const override;
    Storage storage() const override;

private:
    Info info_;
    std::string state_dir_;
    // Path to the sysfs `voltage_now` of the first battery found, empty when
    // there is none. Resolved at construction.
    std::string voltage_path_;
};

}  // namespace clt
