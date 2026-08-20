#include "radio/sx1262.h"

#include <poll.h>

#include <cmath>
#include <algorithm>
#include <string_view>
#include <thread>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace clt::radio {

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
constexpr uint16_t kRegVersionString = 0x0320;  // "SX1261"/"SX1262"/"SX1268"
constexpr uint16_t kRegLoRaSyncWordMsb = 0x0740;
constexpr uint16_t kRegRxGain = 0x08AC;
constexpr uint16_t kRegOcpConfig = 0x08E7;
constexpr uint16_t kRegTxClampConfig = 0x08D8;
constexpr uint16_t kRegSensitivityConfig = 0x0889;

// IRQ bits
constexpr uint16_t kIrqTxDone = 0x0001;
constexpr uint16_t kIrqRxDone = 0x0002;
constexpr uint16_t kIrqPreambleDetected = 0x0004;
constexpr uint16_t kIrqHeaderValid = 0x0010;
constexpr uint16_t kIrqHeaderErr = 0x0020;
constexpr uint16_t kIrqCrcErr = 0x0040;
constexpr uint16_t kIrqTimeout = 0x0200;

// The largest LoRa payload the chip will carry, and so the longest any single
// reception can take.
constexpr size_t kMaxPayloadSize = 255;

// The explicit header is 8 symbols, plus the 4.25-symbol sync that follows the
// preamble. Rounded up, and it only sets how long an unconfirmed preamble is
// believed, so erring high costs a little delay and erring low costs a
// destroyed reception.
constexpr uint16_t kHeaderSymbols = 16;

constexpr uint8_t kPacketTypeLoRa = 0x01;
constexpr uint8_t kStandbyRc = 0x00;

// An unpowered module leaves MISO at all-zeroes or all-ones. A real SX126x
// reports one of the five defined chip modes, plus three explicit command-error
// values that must not be mistaken for a successful SPI transfer.
bool command_status_ok(uint8_t opcode, uint8_t status) {
    const uint8_t chip_mode = (status >> 4) & 0x07;
    const uint8_t command_status = (status >> 1) & 0x07;
    if (chip_mode >= 2 && chip_mode <= 6 && (command_status < 3 || command_status > 5))
        return true;
    LOG_DEBUG("sx1262: command 0x%02x returned error status 0x%02x", opcode, status);
    return false;
}

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

Sx1262::Sx1262(RadioParams params, Pins pins, uint32_t retry_interval_ms)
    : params_(params), pins_(std::move(pins)), retry_interval_ms_(retry_interval_ms) {}

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
            // While the radio is down this is just a retry poking at a chip
            // that is not there; only a working radio going quiet is news.
            if (healthy_) {
                LOG_ERROR("sx1262: BUSY stuck high for %u ms", timeout_ms);
            } else {
                LOG_DEBUG("sx1262: BUSY stuck high for %u ms", timeout_ms);
            }
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

    Bytes rx(tx.size(), 0);
    if (nss_line_ && !nss_line_->set(false)) return false;
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_ && !nss_line_->set(true)) ok = false;
    if (!ok) return false;

    // Write commands clock a status byte back while the first argument is
    // sent. Commands in this driver all have at least one argument.
    return args.empty() || command_status_ok(opcode, rx[1]);
}

bool Sx1262::cmd_read(uint8_t opcode, ByteSpan out) {
    if (!wait_busy()) return false;

    // opcode, status byte, then the response.
    Bytes tx(2 + out.size(), 0x00);
    tx[0] = opcode;
    Bytes rx(tx.size(), 0);

    if (nss_line_ && !nss_line_->set(false)) return false;
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_ && !nss_line_->set(true)) ok = false;
    if (!ok) return false;
    if (!command_status_ok(opcode, rx[1])) return false;

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

    if (nss_line_ && !nss_line_->set(false)) return false;
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_ && !nss_line_->set(true)) ok = false;
    if (!ok) return false;
    if (!command_status_ok(kCmdReadRegister, rx[3])) return false;

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

    if (nss_line_ && !nss_line_->set(false)) return false;
    bool ok = spi_.transfer(tx, rx);
    if (nss_line_ && !nss_line_->set(true)) ok = false;
    if (!ok) return false;
    if (!command_status_ok(kCmdReadBuffer, rx[2])) return false;

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
    if (!reset_line_->set(false)) {
        error = "could not assert the SX1262 reset line";
        return false;
    }
    sleep_ms(2);
    if (!reset_line_->set(true)) {
        error = "could not release the SX1262 reset line";
        return false;
    }
    sleep_ms(20);

    if (!wait_busy(1000)) {
        error = "SX1262 did not release BUSY after reset — check the wiring";
        return false;
    }

    // The SX126x can reject the first few commands after reset even though
    // BUSY is already low.  Wake it into RC standby before attempting a
    // register read; otherwise repeatedly resetting after the rejected probe
    // guarantees that every probe is the first command after a reset.
    const uint32_t deadline = millis() + 1000;
    const uint8_t standby = kStandbyRc;
    while (!cmd(kCmdSetStandby, ByteView(&standby, 1))) {
        if (static_cast<int32_t>(millis() - deadline) >= 0) {
            error = "SX1262 did not accept standby after reset — check the wiring";
            return false;
        }
        sleep_ms(10);
    }
    return true;
}

bool Sx1262::chip_responding() {
    // The part number lives in six registers at 0x0320. An unpowered chip does
    // not drive MISO at all, so the read "succeeds" and comes back as 0x00s (or
    // 0xFFs) — which is exactly how a switched-off LoRa rail looks from here.
    uint8_t version[6] = {0};
    if (!read_register(kRegVersionString, version)) return false;
    return std::string_view(reinterpret_cast<const char*>(version), 5) == "SX126";
}

bool Sx1262::bring_up(std::string& error) {
    if (!reset_chip(error)) return false;

    if (!chip_responding()) {
        error = "SX1262 is not answering — the LoRa power rail is most likely off";
        return false;
    }

    if (!configure(error)) return false;

    if (!set_rx_mode()) {
        error = "could not put the radio into receive mode";
        return false;
    }

    healthy_ = true;
    return true;
}

bool Sx1262::begin(EventLoop& loop, std::string& error) {
    loop_ = &loop;

    if (!spi_.open(pins_.spidev, pins_.spi_speed_hz, error)) return false;
    if (!chip_.open(pins_.gpiochip, error)) return false;

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

    // The IRQ line belongs to the SoC, not to the module, so this watch stays
    // valid across a chip that comes and goes; on_irq() ignores edges while the
    // radio is down.
    irq_watch_ = loop.add_fd(irq_line_->fd(), POLLIN, [this](short) { on_irq(); });

    if (retry_interval_ms_ == 0) {
        if (!bring_up(error)) return false;
        ever_healthy_ = true;
        LOG_INFO("sx1262: %s", describe().c_str());
        return true;
    }

    // One timer covers both halves of supervision: while the radio is up it
    // checks that the chip is still there, and while it is down it starts a
    // recovery attempt. The attempt itself uses short one-shot timers so reset
    // delays and a stuck BUSY line never block the daemon's event loop.
    supervise_timer_ = loop.add_repeating(retry_interval_ms_, [this] { supervise(); });
    start_recovery();
    error.clear();

    return true;
}

void Sx1262::start_recovery() {
    if (!loop_ || healthy_ || recovering_) return;
    recovering_ = true;

    if (!reset_line_) {
        recovery_failed("no reset line configured");
        return;
    }
    if (!reset_line_->set(false)) {
        recovery_failed("could not assert the SX1262 reset line");
        return;
    }

    recovery_timer_ = loop_->add_timer(2, [this] {
        recovery_timer_.reset();
        release_reset();
    });
}

void Sx1262::release_reset() {
    if (!recovering_) return;
    if (!reset_line_->set(true)) {
        recovery_failed("could not release the SX1262 reset line");
        return;
    }

    recovery_deadline_ms_ = millis() + 1000;
    recovery_timer_ = loop_->add_timer(20, [this] {
        recovery_timer_.reset();
        poll_reset_busy();
    });
}

void Sx1262::poll_reset_busy() {
    if (!recovering_) return;

    const int busy = busy_line_ ? busy_line_->get() : 0;
    if (busy < 0) {
        recovery_failed("could not read the SX1262 BUSY line");
        return;
    }
    if (busy > 0) {
        if (static_cast<int32_t>(millis() - recovery_deadline_ms_) >= 0) {
            recovery_failed("SX1262 did not release BUSY after reset — check the wiring");
            return;
        }
        recovery_timer_ = loop_->add_timer(10, [this] {
            recovery_timer_.reset();
            poll_reset_busy();
        });
        return;
    }

    // BUSY going low does not mean the first command will be accepted.  The
    // chip commonly returns command-failed for a short time after reset, so
    // retry RC standby without resetting it again.
    const uint8_t standby = kStandbyRc;
    if (!cmd(kCmdSetStandby, ByteView(&standby, 1))) {
        if (static_cast<int32_t>(millis() - recovery_deadline_ms_) >= 0) {
            recovery_failed("SX1262 did not accept standby after reset — check the wiring");
            return;
        }
        recovery_timer_ = loop_->add_timer(10, [this] {
            recovery_timer_.reset();
            poll_reset_busy();
        });
        return;
    }

    std::string error;
    if (!chip_responding()) {
        recovery_failed("SX1262 is not answering — the LoRa power rail is most likely off");
        return;
    }
    if (!configure(error)) {
        recovery_failed(error);
        return;
    }
    if (!set_rx_mode()) {
        recovery_failed("could not put the radio into receive mode");
        return;
    }

    const bool returning = ever_healthy_;
    healthy_ = true;
    recovering_ = false;
    ever_healthy_ = true;
    if (returning) {
        LOG_INFO("sx1262: radio back up — %s", describe().c_str());
    } else {
        LOG_INFO("sx1262: %s", describe().c_str());
    }
}

void Sx1262::recovery_failed(const std::string& error) {
    recovering_ = false;
    recovery_timer_.reset();
    if (txen_line_) txen_line_->set(false);
    if (rxen_line_) rxen_line_->set(false);
    if (!initial_failure_reported_) {
        LOG_WARN("sx1262: %s — retrying every %u s", error.c_str(), retry_interval_ms_ / 1000);
        initial_failure_reported_ = true;
    } else {
        LOG_DEBUG("sx1262: still down: %s", error.c_str());
    }
}

void Sx1262::supervise() {
    if (recovering_) return;
    if (healthy_) {
        // Don't poke the chip mid-transmission; the next tick will do it.
        if (tx_busy_ || chip_responding()) return;
        go_down("radio stopped answering — was the LoRa power rail turned off?");
        return;
    }

    start_recovery();
}

void Sx1262::go_down(const char* why) {
    if (retry_interval_ms_ > 0) {
        LOG_WARN("sx1262: %s — retrying every %u s", why, retry_interval_ms_ / 1000);
    } else {
        LOG_ERROR("sx1262: %s", why);
    }
    initial_failure_reported_ = true;
    healthy_ = false;
    if (txen_line_) txen_line_->set(false);
    if (rxen_line_) rxen_line_->set(false);

    // Release whatever was waiting on a transmission that will now never
    // complete, or the dispatcher would sit on a busy radio forever.
    if (tx_busy_) {
        tx_busy_ = false;
        tx_timeout_.reset();
        deliver_tx_done(0);
    }
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
        if (!wait_busy()) return fail_with("Calibrate (busy)");

        // The chip tries to start its oscillator at power-up, before DIO3 is
        // driving the TCXO, so XOSC_START_ERR is latched on every cold boot and
        // means nothing by itself. Clear it here; a fault that is real will
        // latch again during the checks below.
        if (!cmd(kCmdClearDeviceErrors, Bytes {0x00, 0x00}))
            return fail_with("ClearDeviceErrors");
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
    if (!read_register(kRegTxClampConfig, ByteSpan(&clamp, 1)))
        return fail_with("read TX clamp configuration");
    clamp |= 0x1E;
    if (!write_register(kRegTxClampConfig, ByteView(&clamp, 1)))
        return fail_with("write TX clamp configuration");

    // Errata 15.1, the other half of the pair: the receiver needs bit 2 of the
    // sensitivity register cleared at 500 kHz and set everywhere else. The
    // power-on state is already right for every other bandwidth, but lora_bw =
    // 500 is a value the config accepts, and RadioLib applies this for MeshCore
    // (SX126x::fixSensitivity). Bandwidth is fixed at configure time here, so
    // this is the only place it has to be applied.
    uint8_t sensitivity = 0;
    if (!read_register(kRegSensitivityConfig, ByteSpan(&sensitivity, 1)))
        return fail_with("read sensitivity configuration");
    if (std::fabs(params_.bw_khz - 500.0) <= 0.001) {
        sensitivity &= static_cast<uint8_t>(~0x04);
    } else {
        sensitivity |= 0x04;
    }
    if (!write_register(kRegSensitivityConfig, ByteView(&sensitivity, 1)))
        return fail_with("write sensitivity configuration");

    // Over-current protection, in 2.5 mA steps.
    uint8_t ocp = static_cast<uint8_t>(std::min(params_.current_limit_ma / 2.5, 63.0));
    if (!write_register(kRegOcpConfig, ByteView(&ocp, 1)))
        return fail_with("over-current protection");

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
    if (!write_register(kRegRxGain, ByteView(&gain, 1))) return fail_with("RX gain");

    if (!cmd(kCmdSetBufferBaseAddress, Bytes {0x00, 0x00}))
        return fail_with("SetBufferBaseAddress");

    // Fall back to standby (not FS) after TX/RX so the PA is not left biased.
    if (!cmd(kCmdSetRxTxFallbackMode, Bytes {0x20}))
        return fail_with("SetRxTxFallbackMode");

    // Two different masks. Everything we act on is routed to DIO1; preamble and
    // header-valid are only latched, so channel_busy() can poll them before a
    // transmission. Routing those to DIO1 as well would wake the event loop for
    // every preamble on the band, which is a lot of wakeups to learn nothing.
    const uint16_t latched = kIrqTxDone | kIrqRxDone | kIrqCrcErr | kIrqHeaderErr | kIrqTimeout |
                             kIrqPreambleDetected | kIrqHeaderValid;
    const uint16_t dio1 = kIrqTxDone | kIrqRxDone | kIrqCrcErr | kIrqHeaderErr | kIrqTimeout;
    Bytes irq_args {static_cast<uint8_t>(latched >> 8), static_cast<uint8_t>(latched),
                    static_cast<uint8_t>(dio1 >> 8),    static_cast<uint8_t>(dio1),
                    0x00, 0x00,   // DIO2 unused (it drives the RF switch)
                    0x00, 0x00};  // DIO3 unused (it powers the TCXO)
    if (!cmd(kCmdSetDioIrqParams, irq_args)) return fail_with("SetDioIrqParams");

    // Now that the TCXO has had time to settle and everything is programmed,
    // any error still latched is a genuine fault worth reporting.
    uint8_t errs[2] = {0, 0};
    if (!cmd_read(kCmdGetDeviceErrors, errs)) return fail_with("GetDeviceErrors");
    uint16_t e = static_cast<uint16_t>(errs[0] << 8 | errs[1]);
    if (e & 0x0020)
        LOG_WARN("sx1262: XOSC_START_ERR persists — check lora_tcxo matches the board "
                 "(1.8 V on AIO v2); RX/TX may still work but frequency accuracy suffers");
    if (e & ~0x0020) LOG_WARN("sx1262: device errors 0x%04x", e);

    return true;
}

bool Sx1262::set_modulation() {
    // sf, bw, cr, low-data-rate optimisation. The last one is derived from the
    // symbol time because that is what RadioLib does for MeshCore; see
    // RadioParams::low_data_rate_optimize.
    Bytes args {params_.sf, bw_code(params_.bw_khz),
                static_cast<uint8_t>(params_.cr - 4),
                static_cast<uint8_t>(params_.low_data_rate_optimize() ? 0x01 : 0x00)};
    return cmd(kCmdSetModulationParams, args);
}

bool Sx1262::set_packet_params(uint8_t payload_len) {
    Bytes args {
        static_cast<uint8_t>(params_.preamble_symbols() >> 8),
        static_cast<uint8_t>(params_.preamble_symbols()),
        0x00,         // explicit (variable length) header
        payload_len,
        0x01,         // CRC on
        0x00,         // standard IQ
    };
    return cmd(kCmdSetPacketParams, args);
}

bool Sx1262::set_rx_mode() {
    if (txen_line_ && !txen_line_->set(false)) return false;
    if (rxen_line_ && !rxen_line_->set(true)) return false;

    if (!cmd(kCmdClearIrqStatus, Bytes {0xFF, 0xFF})) return false;
    // 0xFFFFFF selects continuous receive.
    return cmd(kCmdSetRx, Bytes {0xFF, 0xFF, 0xFF});
}

// ---------------------------------------------------------------------------
// Transmit / receive
// ---------------------------------------------------------------------------

// Symbol time at the configured spreading factor and bandwidth: 2^sf / bw, in
// milliseconds, since bandwidth is already in kHz.
uint32_t Sx1262::symbols_ms(uint32_t symbols) const {
    if (params_.sf < 5 || params_.bw_khz <= 0) return 0;
    const double per_symbol = static_cast<double>(uint32_t {1} << params_.sf) / params_.bw_khz;
    return static_cast<uint32_t>(per_symbol * symbols) + 1;
}

bool Sx1262::channel_busy() {
    // Nothing to protect if the chip is down, and during our own transmission
    // the flags describe the packet we are sending, not one arriving.
    if (!healthy_ || tx_busy_) return false;

    uint8_t status[2] = {0, 0};
    // A chip that will not answer is a bigger problem than a busy channel, and
    // the supervisor is the one that deals with it. Do not block the queue.
    if (!cmd_read(kCmdGetIrqStatus, status)) return false;
    const uint16_t irq = static_cast<uint16_t>(status[0] << 8 | status[1]);

    if (!(irq & (kIrqPreambleDetected | kIrqHeaderValid))) {
        rx_since_ms_ = 0;
        return false;
    }

    const uint32_t now = millis();
    if (rx_since_ms_ == 0) rx_since_ms_ = now;

    // The two stages get very different deadlines, because a preamble detector
    // fires on noise as readily as on a packet. Until a header validates, allow
    // only the time it takes one to arrive; once one has, a real packet is on
    // its way and it gets the longest the chip can carry. Giving an unconfirmed
    // preamble the full packet time instead costs seconds of delay on every
    // transmission that follows a burst of noise — which on a quiet bench is
    // most of them.
    const uint32_t deadline = (irq & kIrqHeaderValid)
                                  ? airtime_ms(kMaxPayloadSize)
                                  : symbols_ms(params_.preamble_symbols() + kHeaderSymbols);
    if (now - rx_since_ms_ > deadline) {
        LOG_TRACE("sx1262: reception flag stale after %u ms, clearing", now - rx_since_ms_);
        constexpr uint16_t stale = kIrqPreambleDetected | kIrqHeaderValid;
        cmd(kCmdClearIrqStatus,
            Bytes {static_cast<uint8_t>(stale >> 8), static_cast<uint8_t>(stale)});
        rx_since_ms_ = 0;
        return false;
    }
    return true;
}

bool Sx1262::send(ByteView data) {
    if (!healthy_ || tx_busy_) return false;
    if (data.empty() || data.size() > 255) return false;

    auto io_failed = [this](const char* what) {
        fail(what);
        return false;
    };

    if (!cmd(kCmdSetStandby, Bytes {kStandbyRc})) return io_failed("entering standby");
    if (!set_packet_params(static_cast<uint8_t>(data.size())))
        return io_failed("setting TX packet parameters");
    if (!cmd(kCmdSetBufferBaseAddress, Bytes {0x00, 0x00}))
        return io_failed("setting the TX buffer address");
    if (!write_buffer(0x00, data)) return io_failed("writing the TX buffer");
    if (!cmd(kCmdClearIrqStatus, Bytes {0xFF, 0xFF}))
        return io_failed("clearing IRQ status before TX");

    if (rxen_line_ && !rxen_line_->set(false)) return io_failed("disabling the RX path");
    if (txen_line_ && !txen_line_->set(true)) return io_failed("enabling the TX path");

    // No hardware timeout: we police it ourselves so a wedged chip surfaces as
    // a log line rather than a silent stall.
    if (!cmd(kCmdSetTx, Bytes {0x00, 0x00, 0x00})) {
        if (txen_line_) txen_line_->set(false);
        return io_failed("starting TX");
    }

    tx_busy_ = true;
    tx_started_ms_ = millis();

    uint32_t expected = airtime_ms(data.size());
    tx_timeout_ = loop_->add_timer(expected + 2000, [this] {
        if (!tx_busy_) return;
        LOG_ERROR("sx1262: transmit timed out, resetting to receive");
        tx_busy_ = false;
        if (!set_rx_mode()) fail("returning to RX after a TX timeout");
        deliver_tx_done(0);
    });
    return true;
}

void Sx1262::on_irq() {
    if (irq_line_->drain_events() < 0) return;
    // An unpowered module can leave DIO1 floating and chattering; there is
    // nothing to read from it until the chip is back.
    if (!healthy_) return;

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

    if (irq & kIrqTxDone) {
        handle_tx_done();
        if (!healthy_) return;
    }

    if (irq & (kIrqCrcErr | kIrqHeaderErr | kIrqTimeout)) {
        // A failed reception usually arrives with no RxDone bit at all: the
        // demodulator locked onto a preamble and gave up before the packet was
        // complete. Report it either way, because the rate of these is the only
        // thing that separates a deaf receiver from a quiet band.
        RxFailure f;
        f.error = irq & kIrqCrcErr      ? RxError::CrcError
                  : irq & kIrqHeaderErr ? RxError::HeaderError
                                        : RxError::Timeout;

        // The chip still holds the packet status for whatever it gave up on,
        // and that is what says which kind of failure this was. Not after a
        // timeout: nothing arrived, so the registers still describe the last
        // packet that did, and reporting those would be an invention.
        if (f.error != RxError::Timeout) {
            uint8_t pkt_status[3] = {0, 0, 0};
            if (cmd_read(kCmdGetPacketStatus, pkt_status)) {
                f.has_signal = true;
                f.rssi = -static_cast<int>(pkt_status[0]) / 2;
                f.snr = static_cast<int8_t>(pkt_status[1]) / 4.0f;
            }
        }

        deliver_rx_error(f);
        if (!set_rx_mode()) fail("returning to RX after a failed reception");
        return;
    }

    if (irq & kIrqRxDone) handle_rx_done();
}

void Sx1262::handle_tx_done() {
    if (!tx_busy_) return;
    tx_busy_ = false;
    tx_timeout_.reset();
    if (txen_line_) txen_line_->set(false);

    uint32_t airtime = millis() - tx_started_ms_;
    if (!set_rx_mode()) fail("returning to RX after TX");
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
        if (!set_rx_mode()) fail("returning to RX after an empty packet");
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
    if (!cmd_read(kCmdGetPacketStatus, pkt_status)) {
        fail("reading packet status");
        return;
    }
    rssi = -static_cast<int>(pkt_status[0]) / 2;
    snr = static_cast<int8_t>(pkt_status[1]) / 4.0f;

    // Re-arm before delivering: the handler may transmit, and it must find the
    // radio in a known state.
    if (!set_rx_mode()) {
        fail("returning to RX after a packet");
        return;
    }
    deliver_rx(RxPacket {std::move(data), rssi, snr, millis()});
}

void Sx1262::fail(const char* what) {
    LOG_ERROR("sx1262: radio I/O failure while %s", what);
    go_down("radio marked down after an I/O failure");
}

void Sx1262::shutdown() {
    // Before the GPIO lines go: the IRQ watch refers to a descriptor they own.
    irq_watch_.reset();
    supervise_timer_.reset();
    recovery_timer_.reset();
    tx_timeout_.reset();
    recovering_ = false;
    tx_busy_ = false;

    if (healthy_) {
        cmd(kCmdSetStandby, Bytes {kStandbyRc});
        // Leave the chip asleep so it does not draw current after we exit. The
        // power rail itself is somebody else's to switch.
        cmd(kCmdSetSleep, Bytes {0x00});
    }
    healthy_ = false;

    irq_line_.reset();
    busy_line_.reset();
    reset_line_.reset();
    nss_line_.reset();
    rxen_line_.reset();
    txen_line_.reset();

    chip_.close();
    spi_.close();
}

std::string Sx1262::describe() const {
    // The preamble is in here because it is the one air setting with no line in
    // the config file to read it off: unset means derived from the spreading
    // factor, so the log is the only place it is visible to compare against a
    // neighbour's.
    std::string s =
        vformat("SX1262 on %s (%.3f MHz, SF%u, BW %.1f kHz, CR 4/%u, %d dBm, %u-symbol preamble)",
                pins_.spidev.c_str(), params_.freq_mhz, params_.sf, params_.bw_khz, params_.cr,
                params_.tx_power_dbm, params_.preamble_symbols());
    if (!healthy_) s += " — not responding";
    return s;
}

}  // namespace clt::radio
