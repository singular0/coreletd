// Frozen MeshCore crypto reference vectors, cross-checked against an independent
// implementation of the protocol. Checked in as a fixture — do not edit.
#pragma once

#include <string_view>

namespace umc::testvec {

inline constexpr std::string_view kSeedA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
inline constexpr std::string_view kPrivA = "3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6fa9d71862a3e5746b571be3d187b0041046f52ebd850c7cbd5fde8ee38473b649";
inline constexpr std::string_view kPubA = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
inline constexpr std::string_view kPrivB = "2d5041945c4da58554a87da7f52fd15b167d20f10505bffe6eb73bc0a7fe89220cc91ac2355c1ee150068d79730a10555ba182d182df975f3c369ef757629d73";
inline constexpr std::string_view kPubB = "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4";
inline constexpr std::string_view kSigA = "fc61aa75384123860bc315eafefff5c484facd5958ab9c13ec2f085d14122cd79f79e1f0472f72a121e2346747f322ef0196ad37292ce4c105aeba9c03c44a07";
inline constexpr std::string_view kSharedAB = "e48c9d28d633f3d1f7389ea43d718ba058409d3384b414d94b2397b35b122409";
inline constexpr std::string_view kSealed = "3cf348ee69bffb49b600dc69923be5b950e2";
inline constexpr std::string_view kSealed16 = "c05b8693553e7d4cf02b1ed82ae448335952";
inline constexpr std::string_view kAckHash = "79551730";

inline constexpr std::string_view kSignedMsg = "MeshCore uConsole AIO v2 test vector";
inline constexpr std::string_view kPlain = "hello mesh";
inline constexpr std::string_view kPlain16 = "exactly16bytes!!";
inline constexpr std::string_view kAckInput = "ack me";

}  // namespace umc::testvec
