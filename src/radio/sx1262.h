#pragma once

#include <memory>
#include <string>

#include "radio/gpio.h"
#include "radio/radio.h"
#include "radio/spidev.h"

namespace clt::radio {

// SX1262 driver over spidev + libgpiod, sized for the uConsole AIO v2 wiring:
// SPI1/CE0, DIO1 on GPIO26, BUSY on GPIO24, RESET on GPIO25, DIO2 driving the
// RF switch and DIO3 powering the TCXO.
//
// The LoRa power rail is not ours to switch: whatever manages the board's
// subsystems owns it, and the chip can appear and disappear underneath us at
// any moment. An absent chip is therefore not a startup error — the driver
// keeps checking, brings the radio up whenever it answers, and drops back to
// checking if it stops answering.
class Sx1262 : public Radio {
public:
    struct Pins {
        std::string spidev = "/dev/spidev1.0";
        std::string gpiochip = "gpiochip0";
        int irq = 26;
        int busy = 24;
        int reset = 25;
        int nss = -1;  // -1 when the SPI controller drives chip select
        int rxen = -1;
        int txen = -1;
        uint32_t spi_speed_hz = 2000000;
    };

    // `retry_interval_ms` is both how long to wait before trying an unresponsive
    // chip again and how often a running radio is checked for one. 0 disables
    // both: begin() then fails outright if the chip does not answer.
    Sx1262(RadioParams params, Pins pins, uint32_t retry_interval_ms);
    ~Sx1262() override;

    bool begin(EventLoop& loop, std::string& error) override;
    void shutdown() override;
    bool send(ByteView data) override;
    bool ready() const override { return healthy_; }
    bool tx_busy() const override { return tx_busy_; }
    const RadioParams& params() const override { return params_; }
    std::string describe() const override;

private:
    // --- low level ---
    bool wait_busy(uint32_t timeout_ms = 20);
    bool cmd(uint8_t opcode, ByteView args = {});
    bool cmd_read(uint8_t opcode, ByteSpan out);
    bool write_register(uint16_t addr, ByteView data);
    bool read_register(uint16_t addr, ByteSpan out);
    bool write_buffer(uint8_t offset, ByteView data);
    bool read_buffer(uint8_t offset, ByteSpan out);

    // --- bring-up and supervision ---
    bool reset_chip(std::string& error);
    // Reads the part number back over SPI. False means nothing is answering,
    // which on this board almost always means the LoRa rail is off.
    bool chip_responding();
    bool bring_up(std::string& error);
    void start_recovery();
    void release_reset();
    void poll_reset_busy();
    void recovery_failed(const std::string& error);
    void supervise();
    void go_down(const char* why);

    // --- configuration ---
    bool configure(std::string& error);
    bool set_modulation();
    bool set_packet_params(uint8_t payload_len);
    bool set_rx_mode();

    // --- interrupt handling ---
    void on_irq();
    void handle_rx_done();
    void handle_tx_done();
    void fail(const char* what);

    RadioParams params_;
    Pins pins_;
    uint32_t retry_interval_ms_;

    SpiDev spi_;
    GpioChip chip_;
    std::unique_ptr<GpioLine> irq_line_;
    std::unique_ptr<GpioLine> busy_line_;
    std::unique_ptr<GpioLine> reset_line_;
    std::unique_ptr<GpioLine> nss_line_;
    std::unique_ptr<GpioLine> rxen_line_;
    std::unique_ptr<GpioLine> txen_line_;

    EventLoop* loop_ = nullptr;
    EventLoop::FdWatch irq_watch_;
    EventLoop::Timer tx_timeout_;
    EventLoop::Timer supervise_timer_;
    // One at a time: each step of a recovery arms the next.
    EventLoop::Timer recovery_timer_;

    bool tx_busy_ = false;
    uint32_t tx_started_ms_ = 0;
    bool healthy_ = false;
    bool recovering_ = false;
    bool ever_healthy_ = false;
    bool initial_failure_reported_ = false;
    uint32_t recovery_deadline_ms_ = 0;
};

}  // namespace clt::radio
