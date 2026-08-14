#include "daemon/host_metrics.h"

#include <sys/statvfs.h>

#include <algorithm>
#include <fstream>

#ifdef __linux__
#include <filesystem>
#endif

#include "util/log.h"

namespace clt {

namespace {

// The uConsole exposes its pack through the standard power-supply class. Only
// Linux has one; elsewhere there is nothing to look for, and iterating a
// directory that does not exist to discover that is wasted work.
std::string find_battery_voltage_path() {
#ifdef __linux__
    namespace fs = std::filesystem;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/sys/class/power_supply", ec)) {
        std::ifstream type_file(entry.path() / "type");
        std::string type;
        if (!(type_file >> type) || type != "Battery") continue;

        fs::path volt = entry.path() / "voltage_now";
        // Presence is not enough: some drivers publish the attribute and then
        // fail the read. Only a path that answers now is worth keeping.
        std::ifstream probe(volt);
        long uv = 0;
        if (probe >> uv && uv > 0) return volt.string();
    }
#endif
    return {};
}

}  // namespace

HostMetrics::HostMetrics(Info info, std::string state_dir)
    : info_(std::move(info)),
      state_dir_(std::move(state_dir)),
      voltage_path_(find_battery_voltage_path()) {
    if (voltage_path_.empty())
        LOG_INFO("metrics: no battery found, reporting voltage as unknown");
    else
        LOG_INFO("metrics: battery at %s", voltage_path_.c_str());
}

uint16_t HostMetrics::battery_mv() const {
    if (voltage_path_.empty()) return 0;

    std::ifstream volt(voltage_path_);
    long uv = 0;
    if (!(volt >> uv) || uv <= 0) return 0;
    return static_cast<uint16_t>(std::min(uv / 1000, 65535L));
}

HostMetrics::Storage HostMetrics::storage() const {
    struct statvfs vfs {};
    if (statvfs(state_dir_.c_str(), &vfs) != 0) return {};

    // f_frsize is the fragment size the block counts are in; f_bsize is the
    // preferred I/O size and is the wrong multiplier here.
    const uint64_t unit = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;
    const uint64_t total = static_cast<uint64_t>(vfs.f_blocks) * unit;
    // Used is simply total minus free, so the app's two numbers always agree
    // with each other. df subtracts the root reservation as well and so reports
    // a slightly smaller figure on filesystems that have one.
    const uint64_t used = static_cast<uint64_t>(vfs.f_blocks - vfs.f_bfree) * unit;
    return {used, total};
}

}  // namespace clt
