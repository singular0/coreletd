#pragma once

#include <memory>
#include <string>

struct gpiod_chip;
struct gpiod_line_request;
struct gpiod_edge_event_buffer;

namespace umc::radio {

// A single requested GPIO line. Each line gets its own request, which keeps
// the SX1262's mixed directions (outputs, a polled BUSY input, and an
// edge-triggered IRQ) independent of each other.
class GpioLine {
public:
    ~GpioLine();
    GpioLine(const GpioLine&) = delete;
    GpioLine& operator=(const GpioLine&) = delete;

    bool set(bool value);
    // Returns -1 on error, otherwise 0 or 1.
    int get() const;

    // Only valid for edge-detection lines: an fd that becomes readable when an
    // edge arrives, suitable for poll().
    int fd() const;
    // Consumes pending edge events. Returns the number consumed, -1 on error.
    int drain_events();

private:
    friend class GpioChip;
    GpioLine(gpiod_line_request* req, unsigned offset, gpiod_edge_event_buffer* buf)
        : req_(req), offset_(offset), events_(buf) {}

    gpiod_line_request* req_ = nullptr;
    unsigned offset_ = 0;
    gpiod_edge_event_buffer* events_ = nullptr;
};

class GpioChip {
public:
    ~GpioChip();

    // `name` may be a bare chip name ("gpiochip0") or a full path.
    bool open(const std::string& name, std::string& error);
    void close();

    std::unique_ptr<GpioLine> request_output(unsigned offset, bool initial, std::string& error);
    std::unique_ptr<GpioLine> request_input(unsigned offset, std::string& error);
    // Input with rising-edge detection, for the SX1262's DIO1 interrupt.
    std::unique_ptr<GpioLine> request_rising_edge(unsigned offset, std::string& error);

private:
    enum class Mode { Output, Input, RisingEdge };
    std::unique_ptr<GpioLine> request(unsigned offset, Mode mode, bool initial,
                                      std::string& error);

    gpiod_chip* chip_ = nullptr;
    std::string path_;
};

}  // namespace umc::radio
