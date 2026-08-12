#pragma once

#include <optional>

#include "util/bytes.h"

namespace umc::companion {

// Command / response / push codes. These mirror the upstream MeshCore
// companion firmware and must never be renumbered — the phone app, meshcore-cli
// and meshtui all hard-code them.

enum Cmd : uint8_t {
    kCmdAppStart = 1,
    kCmdSendTxtMsg = 2,
    kCmdSendChannelTxtMsg = 3,
    kCmdGetContacts = 4,
    kCmdGetDeviceTime = 5,
    kCmdSetDeviceTime = 6,
    kCmdSendSelfAdvert = 7,
    kCmdSetAdvertName = 8,
    kCmdAddUpdateContact = 9,
    kCmdSyncNextMessage = 10,
    kCmdSetRadioParams = 11,
    kCmdSetRadioTxPower = 12,
    kCmdResetPath = 13,
    kCmdSetAdvertLatLon = 14,
    kCmdRemoveContact = 15,
    kCmdShareContact = 16,
    kCmdExportContact = 17,
    kCmdImportContact = 18,
    kCmdReboot = 19,
    kCmdGetBatteryVoltage = 20,
    kCmdSetTuningParams = 21,
    kCmdDeviceQuery = 22,
    kCmdExportPrivateKey = 23,
    kCmdImportPrivateKey = 24,
    kCmdSendRawData = 25,
    kCmdSendLogin = 26,
    kCmdSendStatusReq = 27,
    kCmdHasConnection = 28,
    kCmdLogout = 29,
    kCmdGetContactByKey = 30,
    kCmdGetChannel = 31,
    kCmdSetChannel = 32,
    kCmdSignStart = 33,
    kCmdSignData = 34,
    kCmdSignFinish = 35,
    kCmdSendTracePath = 36,
    kCmdSetDevicePin = 37,
    kCmdSetOtherParams = 38,
    kCmdSendTelemetryReq = 39,
    kCmdGetCustomVars = 40,
    kCmdSetCustomVar = 41,
    kCmdGetAdvertPath = 42,
};

enum Resp : uint8_t {
    kRespOk = 0,
    kRespErr = 1,
    kRespContactsStart = 2,
    kRespContact = 3,
    kRespEndOfContacts = 4,
    kRespSelfInfo = 5,
    kRespSent = 6,
    kRespContactMsgRecv = 7,
    kRespChannelMsgRecv = 8,
    kRespCurrTime = 9,
    kRespNoMoreMessages = 10,
    kRespExportContact = 11,
    kRespBatteryVoltage = 12,
    kRespDeviceInfo = 13,
    kRespPrivateKey = 14,
    kRespDisabled = 15,
    kRespContactMsgRecvV3 = 16,
    kRespChannelMsgRecvV3 = 17,
    kRespChannelInfo = 18,
    kRespSignStart = 19,
    kRespSignature = 20,
    kRespCustomVars = 21,
    kRespAdvertPath = 22,
};

enum Push : uint8_t {
    kPushAdvert = 0x80,
    kPushPathUpdated = 0x81,
    kPushSendConfirmed = 0x82,
    kPushMsgWaiting = 0x83,
    kPushRawData = 0x84,
    kPushLoginSuccess = 0x85,
    kPushLoginFail = 0x86,
    kPushStatusResponse = 0x87,
    kPushLogRxData = 0x88,
    kPushTraceData = 0x89,
    kPushNewAdvert = 0x8A,
    kPushTelemetryResponse = 0x8B,
};

enum Err : uint8_t {
    kErrUnsupportedCmd = 1,
    kErrNotFound = 2,
    kErrTableFull = 3,
    kErrBadState = 4,
    kErrFileIoError = 5,
    kErrIllegalArg = 6,
};

// Firmware protocol version we claim in RESP_CODE_DEVICE_INFO. V3 is the
// message format carrying SNR, which is what current apps expect.
inline constexpr uint8_t kFirmwareVersion = 3;
inline constexpr size_t kContactPathField = 64;
inline constexpr size_t kContactNameField = 32;
inline constexpr size_t kChannelNameField = 32;
inline constexpr size_t kChannelSecretSize = 16;
// out_path_len is a signed byte; -1 means "no route known, use flood".
inline constexpr uint8_t kNoPath = 0xFF;

// Over TCP and serial the frame is length-prefixed. '<' marks app-to-device,
// '>' device-to-app, followed by a uint16 little-endian length.
inline constexpr uint8_t kFrameToDevice = '<';
inline constexpr uint8_t kFrameToApp = '>';
inline constexpr size_t kMaxFrameSize = 8192;

// Incremental de-framer for a byte stream. Resynchronises by discarding bytes
// until a start marker appears, since a half-open TCP connection can leave the
// stream mid-frame.
class FrameReader {
public:
    void feed(ByteView data);
    // Returns the next complete frame payload, or nullopt when more data is
    // needed. Call repeatedly until it returns nullopt.
    std::optional<Bytes> next();
    void reset() { buf_.clear(); }
    size_t buffered() const { return buf_.size(); }

private:
    Bytes buf_;
};

Bytes frame_response(ByteView payload);

// Small helpers for the fixed reply shapes.
Bytes resp_ok();
Bytes resp_ok(uint32_t value);
Bytes resp_err(uint8_t code);

}  // namespace umc::companion
