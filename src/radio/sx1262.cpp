#include "radio/sx1262.h"

#include <poll.h>

#include <cmath>
#include <algorithm>
#include <thread>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::radio {

namespace {

// SX126x opcodes
constexpr uint8_t kCmdSetSleep = 0x84;
constexpr uint8_t kCmdSetStandby = 0x80;
constexpr uint8_t kCmdSetTx = 0x83;
constexpr uint8_t kCmdSetRx = 0x82;
constexpr uint8_t kCmdSetRfFrequency = 0x86;
constexpr uint8_t kCmdSetPacketType = 0x8A;
constexpr uint8_t kCmdSetTxParams = 0x8E;
constexpr uint8_t kCmdSetPaConfig = 0x95;
constexpr uint8_t kCmdSetBufferBaseAddress = 0x8F;
constexpr uint8_t kCmdSetModulationParams = 0x8B;
constexpr uint8_t kCmdSetPacketParams = 0x8C;
constexpr uint8_t kCmdSetDioIrqParams = 0x08;
constexpr uint8_t kCmdGetIrqStatus = 0x12;
constexpr uint8_t kCmdClearIrqStatus = 0x02;
constexpr uint8_t kCmdSetDio2AsRfSwitch = 0x9D;
constexpr uint8_t kCmdSetDio3AsTcxoCtrl = 0x97;
constexpr uint8_t kCmdWriteRegister = 0x0D;
constexpr uint8_t kCmdReadRegister = 0x1D;
constexpr uint8_t kCmdWriteBuffer = 0x0E;
constexpr uint8_t kCmdReadBuffer = 0x1E;
constexpr uint8_t kCmdGetRxBufferStatus = 0x13;
constexpr uint8_t kCmdGetPacketStatus = 0x14;
constexpr uint8_t kCmdCalibrate = 0x89;
constexpr uint8_t kCmdCalibrateImage = 0x98;
constexpr uint8_t kCmdSetRegulatorMode = 0x96;
constexpr uint8_t kCmdGetDeviceErrors = 0x17;
constexpr uint8_t kCmdClearDeviceErrors = 0x07;
constexpr uint8_t kCmdSetRxTxFallbackMode = 0x93;

// Registers
constexpr uint16_t kRegLoRaSyncWordMsb = 0x0740;
constexpr uint16_t kRegRxGain = 0x08AC;
constexpr uint16_t kRegOcpConfig = 0x08E7;
constexpr uint16_t kRegTxClampConfig = 0x08D8;

// IRQ bits
constexpr uint16_t kIrqTxDone = 0x0001;
constexpr uint16_t kIrqRxDone = 0x0002;
constexpr uint16_t kIrqHeaderErr = 0x0020;
constexpr uint16_t kIrqCrcErr = 0x0040;
constexpr uint16_t kIrqTimeout = 0x0200;

constexpr uint8_t kPacketTypeLoRa = 0x01;
constexpr uint8_t kStandbyRc = 0x00;

void sleep_ms(uint32_t ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// LoRa bandwidth register values.
uint8_t bw_code(double khz) {
    struct Entry {
        double khz;
        uint8_t code;
    };
    static constexpr Entry kTable[] = {
        {7.81, 0x00},  {10.42, 0x08}, {15.63, 0x01}, {20.83, 0x09}, {31.25, 0x02},
        {41.67, 0x0A}, {62.5, 0x03},  {125.0, 0x04}, {250.0, 0x05}, {500.0, 0x06},
    };
    uint8_t best = 0x04;
    double best_diff = 1e9;
    for (const auto& e : kTable) {
        double d = std::fabs(e.khz - khz);
        if (d < best_diff) {
            best_diff = d;
            best = e.code;
        }
    }
    return best;
}

}  // namespace

Sx1262::Sx1262(RadioParams params, Pins pins) : params_(params), pins_(std::move(pins)) {}

Sx1262::~Sx1262() { shutdown(); }

// ---------------------------------------------------------------------------
// Low level SPI
// ---------------------------------------------------------------------------

bool Sx1262::wait_busy(uint32_t timeout_ms) {
    if (!busy_line_) return true;
    uint32_t start = millis();
    for (;;) {
        int v = busy_line_->get();
        if (v == 0) return true;
        if (v < 0) return false;
        if (millis() - start > timeout_ms) {
            LOG_ERROR("sx1262: BUSY stuck high for %u ms", timeout_ms);
            return false;
        }
        // The chip clears BUSY within microseconds for most commands; a short
        // sleep keeps us off the CPU without adding meaningful latency.
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

bool Sx1262::cmd(uint8_t opcode, ByteView args) {
    if (!wait_busy()) return false;

    Bytes tx;
    tx.reserve(1 + args.size());
    tx.push_back(opcode);
    tx.insert(tx.end(), args.begin(), args.end());

    if (nss_line_) nss_line_->set(false);
    bool ok = spi_.write(tx);
    if (nss_line_) nss_line_->set(true);
    return ok;
}

bool Sx1262::cmd_read(uint8_t opcode, ByteSpan out) {
    if (!wait_busy()) return false;

    // opcode, status byte, then the response.
    Bytes tx(2 + out.size(), 0x00);
    tx[0] = opcode;
    Bytes rx(tx.size(), 0);

    if (nss_line_) nss_line_->set(false);
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_) nss_line_->set(true);
    if (!ok) return false;

    std::copy(rx.begin() + 2, rx.end(), out.begin());
    return true;
}

bool Sx1262::write_register(uint16_t addr, ByteView data) {
    Bytes args;
    args.reserve(2 + data.size());
    args.push_back(static_cast<uint8_t>(addr >> 8));
    args.push_back(static_cast<uint8_t>(addr));
    args.insert(args.end(), data.begin(), data.end());
    return cmd(kCmdWriteRegister, args);
}

bool Sx1262::read_register(uint16_t addr, ByteSpan out) {
    if (!wait_busy()) return false;

    // opcode, addr hi, addr lo, dummy, then data.
    Bytes tx(4 + out.size(), 0x00);
    tx[0] = kCmdReadRegister;
    tx[1] = static_cast<uint8_t>(addr >> 8);
    tx[2] = static_cast<uint8_t>(addr);
    Bytes rx(tx.size(), 0);

    if (nss_line_) nss_line_->set(false);
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_) nss_line_->set(true);
    if (!ok) return false;

    std::copy(rx.begin() + 4, rx.end(), out.begin());
    return true;
}

bool Sx1262::write_buffer(uint8_t offset, ByteView data) {
    Bytes args;
    args.reserve(1 + data.size());
    args.push_back(offset);
    args.insert(args.end(), data.begin(), data.end());
    return cmd(kCmdWriteBuffer, args);
}

bool Sx1262::read_buffer(uint8_t offset, ByteSpan out) {
    if (!wait_busy()) return false;

    // opcode, offset, dummy, then data.
    Bytes tx(3 + out.size(), 0x00);
    tx[0] = kCmdReadBuffer;
    tx[1] = offset;
    Bytes rx(tx.size(), 0);

    if (nss_line_) nss_line_->set(false);
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_) nss_line_->set(true);
    if (!ok) return false;

    std::copy(rx.begin() + 3, rx.end(), out.begin());
    return true;
}

// ---------------------------------------------------------------------------
// Bring-up
// ---------------------------------------------------------------------------

bool Sx1262::reset_chip(std::string& error) {
    if (!reset_line_) {
        error = "no reset line configured";
        return false;
    }
    // Datasheet asks for at least 100 us low; be generous, this happens once.
    reset_line_->set(false);
    sleep_ms(2);
    reset_line_->set(true);
    sleep_ms(20);

    if (!wait_busy(1000)) {
        error =
            "SX1262 did not release BUSY after reset — check wiring, and that the LoRa "
            "power rail (lora_power_enable_pin) is enabled";
        return false;
    }
    return true;
}

bool Sx1262::begin(EventLoop& loop, std::string& error) {
    loop_ = &loop;

    if (!spi_.open(pins_.spidev, pins_.spi_speed_hz, error)) return false;
    if (!chip_.open(pins_.gpiochip, error)) return false;

    // Power the LoRa section first: on the AIO v2 the SX1262 is unpowered until
    // GPIO16 goes high, and every SPI read would come back as 0x00.
    if (pins_.power_enable >= 0) {
        power_line_ = chip_.request_output(pins_.power_enable, true, error);
        if (!power_line_) return false;
        LOG_DEBUG("sx1262: LoRa power enabled on GPIO%d", pins_.power_enable);
        sleep_ms(50);
    }

    if (pins_.reset < 0 || pins_.busy < 0 || pins_.irq < 0) {
        error = "lora_reset_pin, lora_busy_pin and lora_irq_pin are all required";
        return false;
    }

    reset_line_ = chip_.request_output(pins_.reset, true, error);
    if (!reset_line_) return false;
    busy_line_ = chip_.request_input(pins_.busy, error);
    if (!busy_line_) return false;
    irq_line_ = chip_.request_rising_edge(pins_.irq, error);
    if (!irq_line_) return false;

    if (pins_.nss >= 0) {
        nss_line_ = chip_.request_output(pins_.nss, true, error);
        if (!nss_line_) return false;
    }
    if (pins_.rxen >= 0) {
        rxen_line_ = chip_.request_output(pins_.rxen, false, error);
        if (!rxen_line_) return false;
    }
    if (pins_.txen >= 0) {
        txen_line_ = chip_.request_output(pins_.txen, false, error);
        if (!txen_line_) return false;
    }

    if (!reset_chip(error)) return false;
    if (!configure(error)) return false;

    irq_watch_ = loop.add_fd(irq_line_->fd(), POLLIN, [this](short) { on_irq(); });

    if (!set_rx_mode()) {
        error = "could not put the radio into receive mode";
        return false;
    }

    healthy_ = true;
    LOG_INFO("sx1262: %s", describe().c_str());
    return true;
}

bool Sx1262::configure(std::string& error) {
    auto fail_with = [&](const char* what) {
        error = std::string("SX1262 configuration failed at ") + what;
        return false;
    };

    if (!cmd(kCmdSetStandby, Bytes {kStandbyRc})) return fail_with("SetStandby");

    // DIO3 supplies the TCXO. This must happen before calibration, or the
    // calibration runs against an unstable reference.
    if (params_.tcxo_voltage > 0) {
        uint8_t voltage_code;
        double v = params_.tcxo_voltage;
        if (v <= 1.65) voltage_code = 0x00;       // 1.6V
        else if (v <= 1.75) voltage_code = 0x01;  // 1.7V
        else if (v <= 2.0) voltage_code = 0x02;   // 1.8V
        else if (v <= 2.3) voltage_code = 0x03;   // 2.2V
        else if (v <= 2.55) voltage_code = 0x04;  // 2.4V
        else if (v <= 2.85) voltage_code = 0x05;  // 2.7V
        else if (v <= 3.15) voltage_code = 0x06;  // 3.0V
        else voltage_code = 0x07;                 // 3.3V

        // 10 ms startup delay, in 15.625 us steps.
        const uint32_t delay = 0x0140;
        Bytes args {voltage_code, static_cast<uint8_t>(delay >> 16),
                    static_cast<uint8_t>(delay >> 8), static_cast<uint8_t>(delay)};
        if (!cmd(kCmdSetDio3AsTcxoCtrl, args)) return fail_with("SetDio3AsTcxoCtrl");

        // Recalibrate everything now that the TCXO is running.
        if (!cmd(kCmdCalibrate, Bytes {0x7F})) return fail_with("Calibrate");
        sleep_ms(5);
        if (!wait_busy(1000)) return fail_with("Calibrate (busy)");

        // The chip tries to start its oscillator at power-up, before DIO3 is
        // driving the TCXO, so XOSC_START_ERR is latched on every cold boot and
        // means nothing by itself. Clear it here; a fault that is real will
        // latch again during the checks below.
        cmd(kCmdClearDeviceErrors, Bytes {0x00, 0x00});
    }

    if (!cmd(kCmdSetRegulatorMode, Bytes {0x01})) return fail_with("SetRegulatorMode");  // DC-DC

    if (params_.dio2_as_rf_switch) {
        if (!cmd(kCmdSetDio2AsRfSwitch, Bytes {0x01})) return fail_with("SetDio2AsRfSwitch");
    }

    if (!cmd(kCmdSetPacketType, Bytes {kPacketTypeLoRa})) return fail_with("SetPacketType");

    // Frequency: freq * 2^25 / 32 MHz.
    const uint32_t frf =
        static_cast<uint32_t>((params_.freq_mhz * 1e6) / 32e6 * (1u << 25) + 0.5);
    Bytes freq_args {static_cast<uint8_t>(frf >> 24), static_cast<uint8_t>(frf >> 16),
                     static_cast<uint8_t>(frf >> 8), static_cast<uint8_t>(frf)};
    if (!cmd(kCmdSetRfFrequency, freq_args)) return fail_with("SetRfFrequency");

    // Image calibration for the band in use.
    uint8_t img_lo, img_hi;
    if (params_.freq_mhz >= 900) {
        img_lo = 0xE1;
        img_hi = 0xE9;
    } else if (params_.freq_mhz >= 850) {
        img_lo = 0xD7;
        img_hi = 0xDB;
    } else if (params_.freq_mhz >= 770) {
        img_lo = 0xC1;
        img_hi = 0xC5;
    } else {
        img_lo = 0x6B;
        img_hi = 0x6F;
    }
    if (!cmd(kCmdCalibrateImage, Bytes {img_lo, img_hi})) return fail_with("CalibrateImage");

    // SX1262 high-power PA.
    if (!cmd(kCmdSetPaConfig, Bytes {0x04, 0x07, 0x00, 0x01})) return fail_with("SetPaConfig");

    // Workaround from the datasheet errata: raise the TX clamp threshold to
    // avoid reduced power output on the high-power PA.
    uint8_t clamp = 0;
    if (read_register(kRegTxClampConfig, ByteSpan(&clamp, 1))) {
        clamp |= 0x1E;
        write_register(kRegTxClampConfig, ByteView(&clamp, 1));
    }

    // Over-current protection, in 2.5 mA steps.
    uint8_t ocp = static_cast<uint8_t>(std::min(params_.current_limit_ma / 2.5, 63.0));
    write_register(kRegOcpConfig, ByteView(&ocp, 1));

    int8_t power = static_cast<int8_t>(std::clamp(params_.tx_power_dbm, -9, 22));
    if (!cmd(kCmdSetTxParams, Bytes {static_cast<uint8_t>(power), 0x04 /* 200us ramp */}))
        return fail_with("SetTxParams");

    if (!set_modulation()) return fail_with("SetModulationParams");
    if (!set_packet_params(0xFF)) return fail_with("SetPacketParams");

    // MeshCore uses the "private network" sync word 0x12, which the SX126x
    // stores nibble-expanded across two registers.
    Bytes sync {static_cast<uint8_t>((params_.sync_word & 0xF0) | 0x04),
                static_cast<uint8_t>(((params_.sync_word & 0x0F) << 4) | 0x04)};
    if (!write_register(kRegLoRaSyncWordMsb, sync)) return fail_with("sync word");

    uint8_t gain = params_.rx_boosted_gain ? 0x96 : 0x94;
    write_register(kRegRxGain, ByteView(&gain, 1));

    if (!cmd(kCmdSetBufferBaseAddress, Bytes {0x00, 0x00}))
        return fail_with("SetBufferBaseAddress");

    // Fall back to standby (not FS) after TX/RX so the PA is not left biased.
    cmd(kCmdSetRxTxFallbackMode, Bytes {0x20});

    // Route everything we care about to DIO1.
    const uint16_t mask = kIrqTxDone | kIrqRxDone | kIrqCrcErr | kIrqHeaderErr | kIrqTimeout;
    Bytes irq_args {static_cast<uint8_t>(mask >> 8), static_cast<uint8_t>(mask),
                    static_cast<uint8_t>(mask >> 8), static_cast<uint8_t>(mask),
                    0x00, 0x00,   // DIO2 unused (it drives the RF switch)
                    0x00, 0x00};  // DIO3 unused (it powers the TCXO)
    if (!cmd(kCmdSetDioIrqParams, irq_args)) return fail_with("SetDioIrqParams");

    // Now that the TCXO has had time to settle and everything is programmed,
    // any error still latched is a genuine fault worth reporting.
    uint8_t errs[2] = {0, 0};
    if (cmd_read(kCmdGetDeviceErrors, errs)) {
        uint16_t e = static_cast<uint16_t>(errs[0] << 8 | errs[1]);
        if (e & 0x0020)
            LOG_WARN("sx1262: XOSC_START_ERR persists — check lora_tcxo matches the board "
                     "(1.8 V on AIO v2); RX/TX may still work but frequency accuracy suffers");
        if (e & ~0x0020) LOG_WARN("sx1262: device errors 0x%04x", e);
    }

    return true;
}

bool Sx1262::set_modulation() {
    // sf, bw, cr, low-data-rate optimisation. MeshCore leaves LDRO off.
    Bytes args {params_.sf, bw_code(params_.bw_khz),
                static_cast<uint8_t>(params_.cr - 4), 0x00};
    return cmd(kCmdSetModulationParams, args);
}

bool Sx1262::set_packet_params(uint8_t payload_len) {
    Bytes args {
        static_cast<uint8_t>(params_.preamble >> 8),
        static_cast<uint8_t>(params_.preamble),
        0x00,         // explicit (variable length) header
        payload_len,
        0x01,         // CRC on
        0x00,         // standard IQ
    };
    return cmd(kCmdSetPacketParams, args);
}

bool Sx1262::set_rx_mode() {
    if (rxen_line_) rxen_line_->set(true);
    if (txen_line_) txen_line_->set(false);

    if (!cmd(kCmdClearIrqStatus, Bytes {0xFF, 0xFF})) return false;
    // 0xFFFFFF selects continuous receive.
    return cmd(kCmdSetRx, Bytes {0xFF, 0xFF, 0xFF});
}

// ---------------------------------------------------------------------------
// Transmit / receive
// ---------------------------------------------------------------------------

bool Sx1262::send(ByteView data) {
    if (!healthy_ || tx_busy_) return false;
    if (data.empty() || data.size() > 255) return false;

    if (!cmd(kCmdSetStandby, Bytes {kStandbyRc})) return false;
    if (!set_packet_params(static_cast<uint8_t>(data.size()))) return false;
    if (!cmd(kCmdSetBufferBaseAddress, Bytes {0x00, 0x00})) return false;
    if (!write_buffer(0x00, data)) return false;
    if (!cmd(kCmdClearIrqStatus, Bytes {0xFF, 0xFF})) return false;

    if (txen_line_) txen_line_->set(true);
    if (rxen_line_) rxen_line_->set(false);

    // No hardware timeout: we police it ourselves so a wedged chip surfaces as
    // a log line rather than a silent stall.
    if (!cmd(kCmdSetTx, Bytes {0x00, 0x00, 0x00})) {
        if (txen_line_) txen_line_->set(false);
        return false;
    }

    tx_busy_ = true;
    tx_started_ms_ = millis();

    uint32_t expected = airtime_ms(data.size());
    tx_timeout_ = loop_->add_timer(expected + 2000, [this] {
        if (!tx_busy_) return;
        LOG_ERROR("sx1262: transmit timed out, resetting to receive");
        tx_busy_ = false;
        set_rx_mode();
        deliver_tx_done(0);
    });
    return true;
}

void Sx1262::on_irq() {
    if (irq_line_->drain_events() < 0) return;

    uint8_t status[2] = {0, 0};
    if (!cmd_read(kCmdGetIrqStatus, status)) {
        fail("reading IRQ status");
        return;
    }
    uint16_t irq = static_cast<uint16_t>(status[0] << 8 | status[1]);
    if (irq == 0) return;

    if (!cmd(kCmdClearIrqStatus, Bytes {static_cast<uint8_t>(irq >> 8),
                                        static_cast<uint8_t>(irq)})) {
        fail("clearing IRQ status");
        return;
    }
    LOG_TRACE("sx1262: irq 0x%04x", irq);

    if (irq & kIrqTxDone) handle_tx_done();

    if (irq & kIrqRxDone) {
        // A CRC error means the packet is corrupt; count it and re-arm rather
        // than handing garbage up the stack.
        if (irq & (kIrqCrcErr | kIrqHeaderErr)) {
            LOG_DEBUG("sx1262: dropping packet with %s",
                      (irq & kIrqCrcErr) ? "CRC error" : "header error");
            set_rx_mode();
        } else {
            handle_rx_done();
        }
    } else if (irq & (kIrqCrcErr | kIrqHeaderErr | kIrqTimeout)) {
        set_rx_mode();
    }
}

void Sx1262::handle_tx_done() {
    if (!tx_busy_) return;
    tx_busy_ = false;
    loop_->cancel_timer(tx_timeout_);
    if (txen_line_) txen_line_->set(false);

    uint32_t airtime = millis() - tx_started_ms_;
    set_rx_mode();
    deliver_tx_done(airtime);
}

void Sx1262::handle_rx_done() {
    uint8_t buf_status[2] = {0, 0};
    if (!cmd_read(kCmdGetRxBufferStatus, buf_status)) {
        fail("reading RX buffer status");
        return;
    }
    const uint8_t len = buf_status[0];
    const uint8_t offset = buf_status[1];

    if (len == 0) {
        set_rx_mode();
        return;
    }

    Bytes data(len);
    if (!read_buffer(offset, data)) {
        fail("reading RX buffer");
        return;
    }

    uint8_t pkt_status[3] = {0, 0, 0};
    int rssi = 0;
    float snr = 0.0f;
    if (cmd_read(kCmdGetPacketStatus, pkt_status)) {
        rssi = -static_cast<int>(pkt_status[0]) / 2;
        snr = static_cast<int8_t>(pkt_status[1]) / 4.0f;
    }

    // Re-arm before delivering: the handler may transmit, and it must find the
    // radio in a known state.
    set_rx_mode();
    deliver_rx(RxPacket {std::move(data), rssi, snr, millis()});
}

void Sx1262::fail(const char* what) {
    LOG_ERROR("sx1262: SPI failure while %s — radio marked unhealthy", what);
    healthy_ = false;
}

void Sx1262::shutdown() {
    if (loop_ && irq_line_) loop_->remove_fd(irq_watch_);
    if (healthy_) {
        cmd(kCmdSetStandby, Bytes {kStandbyRc});
        // Leave the chip asleep so it does not draw current after we exit.
        cmd(kCmdSetSleep, Bytes {0x00});
    }
    healthy_ = false;

    irq_line_.reset();
    busy_line_.reset();
    reset_line_.reset();
    nss_line_.reset();
    rxen_line_.reset();
    txen_line_.reset();
    // Cut the LoRa rail last.
    if (power_line_) power_line_->set(false);
    power_line_.reset();

    chip_.close();
    spi_.close();
}

std::string Sx1262::describe() const {
    return vformat("SX1262 on %s (%.3f MHz, SF%u, BW %.1f kHz, CR 4/%u, %d dBm)",
                   pins_.spidev.c_str(), params_.freq_mhz, params_.sf, params_.bw_khz,
                   params_.cr, params_.tx_power_dbm);
}

}  // namespace umc::radio
