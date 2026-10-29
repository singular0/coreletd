#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace clt::companion {

// Where the settings an app changes go. Session turns each command into the
// config keys it sets, written as a line of the settings file would write
// them; the daemon checks them exactly as it checks that file, keeps them, and
// applies them to the running node. Session never sees the config itself.
class Settings {
public:
    enum class Result {
        Ok,
        // A value the settings file would refuse too: ERR_ILLEGAL_ARG.
        Invalid,
        // Checked, but not written, so not applied either: ERR_FILE_IO_ERROR.
        IoError,
    };
    // A dotted config key, such as "radio.lora_sf", and its new value.
    using Change = std::pair<std::string_view, std::string>;

    virtual ~Settings() = default;

    // All or nothing: one change the file would refuse refuses the lot.
    virtual Result set(const std::vector<Change>& changes) = 0;
};

}  // namespace clt::companion
