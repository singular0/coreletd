#include "radio/spidev.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/spi/spidev.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "util/log.h"

namespace clt::radio {

SpiDev::~SpiDev() { close(); }

bool SpiDev::open(const std::string& path, uint32_t speed_hz, std::string& error) {
    fd_ = ::open(path.c_str(), O_RDWR);
    if (fd_ < 0) {
        error = "cannot open " + path + ": " + strerror(errno);
        if (errno == ENOENT)
            error += " (is the SPI overlay enabled? uConsole AIO v2 needs dtoverlay=spi1-1cs)";
        else if (errno == EACCES)
            error += " (add your user to the spi group, or install the udev rule)";
        return false;
    }

    // SX126x uses SPI mode 0, MSB first, 8 bits per word.
    uint8_t mode = SPI_MODE_0;
    uint8_t bits = 8;
    speed_hz_ = speed_hz;

    if (::ioctl(fd_, SPI_IOC_WR_MODE, &mode) < 0 ||
        ::ioctl(fd_, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
        ::ioctl(fd_, SPI_IOC_WR_MAX_SPEED_HZ, &speed_hz_) < 0) {
        error = "cannot configure " + path + ": " + strerror(errno);
        close();
        return false;
    }

    LOG_DEBUG("spi: %s open at %u Hz, mode 0", path.c_str(), speed_hz_);
    return true;
}

void SpiDev::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool SpiDev::transfer(ByteView tx, ByteSpan rx) {
    if (fd_ < 0) return false;
    if (!rx.empty() && rx.size() != tx.size()) return false;

    spi_ioc_transfer xfer {};
    xfer.tx_buf = reinterpret_cast<uintptr_t>(tx.data());
    xfer.rx_buf = rx.empty() ? 0 : reinterpret_cast<uintptr_t>(rx.data());
    xfer.len = static_cast<uint32_t>(tx.size());
    xfer.speed_hz = speed_hz_;
    xfer.bits_per_word = 8;

    if (::ioctl(fd_, SPI_IOC_MESSAGE(1), &xfer) < 0) {
        LOG_ERROR("spi: transfer of %zu bytes failed: %s", tx.size(), strerror(errno));
        return false;
    }
    return true;
}

}  // namespace clt::radio
