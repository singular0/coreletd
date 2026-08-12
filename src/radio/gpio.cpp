#include "radio/gpio.h"

#include <errno.h>
#include <gpiod.h>
#include <string.h>

#include "util/log.h"

namespace umc::radio {

namespace {
constexpr const char* kConsumer = "umeshcore";
constexpr size_t kEventBufferSize = 16;
}  // namespace

GpioLine::~GpioLine() {
    if (events_) gpiod_edge_event_buffer_free(events_);
    if (req_) gpiod_line_request_release(req_);
}

bool GpioLine::set(bool value) {
    if (!req_) return false;
    gpiod_line_value v = value ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE;
    if (gpiod_line_request_set_value(req_, offset_, v) != 0) {
        LOG_ERROR("gpio: cannot set line %u: %s", offset_, strerror(errno));
        return false;
    }
    return true;
}

int GpioLine::get() const {
    if (!req_) return -1;
    gpiod_line_value v = gpiod_line_request_get_value(req_, offset_);
    if (v == GPIOD_LINE_VALUE_ERROR) return -1;
    return v == GPIOD_LINE_VALUE_ACTIVE ? 1 : 0;
}

int GpioLine::fd() const { return req_ ? gpiod_line_request_get_fd(req_) : -1; }

int GpioLine::drain_events() {
    if (!req_ || !events_) return -1;
    int n = gpiod_line_request_read_edge_events(req_, events_, kEventBufferSize);
    if (n < 0) {
        // EAGAIN just means another reader got there first.
        if (errno == EAGAIN) return 0;
        LOG_ERROR("gpio: reading edge events failed: %s", strerror(errno));
        return -1;
    }
    return n;
}

GpioChip::~GpioChip() { close(); }

bool GpioChip::open(const std::string& name, std::string& error) {
    path_ = name.find('/') == std::string::npos ? "/dev/" + name : name;

    chip_ = gpiod_chip_open(path_.c_str());
    if (!chip_) {
        error = "cannot open " + path_ + ": " + strerror(errno);
        if (errno == ENOENT)
            error +=
                " (on a Pi 5 / CM5 the header is usually gpiochip4 or pinctrl-rp1, "
                "set lora_gpiochip accordingly)";
        else if (errno == EACCES)
            error += " (add your user to the gpio group, or install the udev rule)";
        return false;
    }
    LOG_DEBUG("gpio: opened %s", path_.c_str());
    return true;
}

void GpioChip::close() {
    if (chip_) {
        gpiod_chip_close(chip_);
        chip_ = nullptr;
    }
}

std::unique_ptr<GpioLine> GpioChip::request(unsigned offset, Mode mode, bool initial,
                                            std::string& error) {
    if (!chip_) {
        error = "gpio chip not open";
        return nullptr;
    }

    gpiod_line_settings* settings = gpiod_line_settings_new();
    gpiod_line_config* line_cfg = gpiod_line_config_new();
    gpiod_request_config* req_cfg = gpiod_request_config_new();

    std::unique_ptr<GpioLine> result;
    gpiod_line_request* request = nullptr;
    gpiod_edge_event_buffer* events = nullptr;

    if (!settings || !line_cfg || !req_cfg) {
        error = "out of memory configuring gpio line";
        goto cleanup;
    }

    switch (mode) {
        case Mode::Output:
            gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_OUTPUT);
            gpiod_line_settings_set_output_value(
                settings, initial ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE);
            break;
        case Mode::Input:
            gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
            break;
        case Mode::RisingEdge:
            gpiod_line_settings_set_direction(settings, GPIOD_LINE_DIRECTION_INPUT);
            gpiod_line_settings_set_edge_detection(settings, GPIOD_LINE_EDGE_RISING);
            // The SX1262 drives DIO1 actively; no bias needed.
            gpiod_line_settings_set_bias(settings, GPIOD_LINE_BIAS_DISABLED);
            break;
    }

    if (gpiod_line_config_add_line_settings(line_cfg, &offset, 1, settings) != 0) {
        error = "cannot add gpio line " + std::to_string(offset) + ": " + strerror(errno);
        goto cleanup;
    }
    gpiod_request_config_set_consumer(req_cfg, kConsumer);

    request = gpiod_chip_request_lines(chip_, req_cfg, line_cfg);
    if (!request) {
        error = "cannot request gpio line " + std::to_string(offset) + " on " + path_ + ": " +
                strerror(errno);
        if (errno == EBUSY)
            error += " (another process holds it — meshtasticd or a device-tree overlay?)";
        goto cleanup;
    }

    if (mode == Mode::RisingEdge) {
        events = gpiod_edge_event_buffer_new(kEventBufferSize);
        if (!events) {
            error = "cannot allocate edge event buffer";
            gpiod_line_request_release(request);
            goto cleanup;
        }
    }

    result.reset(new GpioLine(request, offset, events));
    LOG_DEBUG("gpio: line %u requested (%s)", offset,
              mode == Mode::Output ? "output" : mode == Mode::Input ? "input" : "rising-edge");

cleanup:
    if (req_cfg) gpiod_request_config_free(req_cfg);
    if (line_cfg) gpiod_line_config_free(line_cfg);
    if (settings) gpiod_line_settings_free(settings);
    return result;
}

std::unique_ptr<GpioLine> GpioChip::request_output(unsigned offset, bool initial,
                                                   std::string& error) {
    return request(offset, Mode::Output, initial, error);
}

std::unique_ptr<GpioLine> GpioChip::request_input(unsigned offset, std::string& error) {
    return request(offset, Mode::Input, false, error);
}

std::unique_ptr<GpioLine> GpioChip::request_rising_edge(unsigned offset, std::string& error) {
    return request(offset, Mode::RisingEdge, false, error);
}

}  // namespace umc::radio
