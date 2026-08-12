#pragma once

#include <memory>
#include <string>

#include "radio/gpio.h"
#include "radio/radio.h"
#include "radio/spidev.h"

namespace umc::radio {

// SX1262 driver over spidev + libgpiod, sized for the uConsole AIO v2 wiring:
// SPI1/CE0, DIO1 on GPIO26, BUSY on GPIO24, RESET on GPIO25, DIO2 driving the
// RF switch and DIO3 powering the TCXO. GPIO16 gates power to the LoRa section
// and must be driven high before the chip will answer.
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
        int power_enable = 16;
        uint32_t spi_speed_hz = 2000000;
    };

    Sx1262(RadioParams params, Pins pins);
    ~Sx1262() override;

    bool begin(EventLoop& loop, std::string& error) override;
    void shutdown() override;
    bool send(ByteView data) override;
    bool tx_busy() const override { return tx_busy_; }
    const RadioParams& params() const override { return params_; }
    std::string describe() const override;

private:
    // --- low level ---
    bool wait_busy(uint32_t timeout_ms = 100);
    bool cmd(uint8_t opcode, ByteView args = {});
    bool cmd_read(uint8_t opcode, ByteSpan out);
    bool write_register(uint16_t addr, ByteView data);
    bool read_register(uint16_t addr, ByteSpan out);
    bool write_buffer(uint8_t offset, ByteView data);
    bool read_buffer(uint8_t offset, ByteSpan out);

    // --- configuration ---
    bool reset_chip(std::string& error);
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

    SpiDev spi_;
    GpioChip chip_;
    std::unique_ptr<GpioLine> irq_line_;
    std::unique_ptr<GpioLine> busy_line_;
    std::unique_ptr<GpioLine> reset_line_;
    std::unique_ptr<GpioLine> nss_line_;
    std::unique_ptr<GpioLine> rxen_line_;
    std::unique_ptr<GpioLine> txen_line_;
    std::unique_ptr<GpioLine> power_line_;

    EventLoop* loop_ = nullptr;
    EventLoop::WatchId irq_watch_ = 0;
    EventLoop::TimerId tx_timeout_ = 0;

    bool tx_busy_ = false;
    uint32_t tx_started_ms_ = 0;
    bool healthy_ = false;
};

}  // namespace umc::radio
