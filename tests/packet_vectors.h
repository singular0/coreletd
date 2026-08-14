// Frozen MeshCore packet/payload reference vectors, cross-checked against an
// independent codec for the same wire format. Checked in as a fixture — do not edit.
#pragma once

#include <cstdint>
#include <string_view>

namespace clt::pktvec {

inline constexpr std::string_view kAdvertPacket = "110003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8245b3a6902791ff01db6cc4b07a2101915cecd66941016fb8238da492290e9b39331f10edd85d46c7d4a8a7c6e5a3e2d3aea1909dbf7be572776fe2dd8390e82c9414f0591c8f01103c80cfeff75436f6e736f6c65";
inline constexpr std::string_view kAdvertPayload = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8245b3a6902791ff01db6cc4b07a2101915cecd66941016fb8238da492290e9b39331f10edd85d46c7d4a8a7c6e5a3e2d3aea1909dbf7be572776fe2dd8390e82c9414f0591c8f01103c80cfeff75436f6e736f6c65";
inline constexpr std::string_view kAdvertAppData = "91c8f01103c80cfeff75436f6e736f6c65";
inline constexpr std::string_view kTextPacket = "09004f03830aa8a96a3176fdbd427de632b42e343875";
inline constexpr std::string_view kTextPlaintext = "245b3a690068656c6c6f206d657368";
inline constexpr std::string_view kTextAckHash = "e08719f5";
inline constexpr std::string_view kAckPacket = "0e00e08719f5";
inline constexpr std::string_view kSharedAB = "e48c9d28d633f3d1f7389ea43d718ba058409d3384b414d94b2397b35b122409";
inline constexpr std::string_view kPubA = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
inline constexpr std::string_view kPubB = "4fd099ccd47d7893dfe9ec24414ecb0d9b5420232aad30d91c465be33cbe65c4";
inline constexpr std::string_view kPrivA = "3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6fa9d71862a3e5746b571be3d187b0041046f52ebd850c7cbd5fde8ee38473b649";
inline constexpr std::string_view kPrivB = "2d5041945c4da58554a87da7f52fd15b167d20f10505bffe6eb73bc0a7fe89220cc91ac2355c1ee150068d79730a10555ba182d182df975f3c369ef757629d73";

inline constexpr uint32_t kFixedTime = 1765432100;
inline constexpr std::string_view kNameA = "uConsole";
inline constexpr std::string_view kTextBody = "hello mesh";
inline constexpr int32_t kLatE6 = 51507400;
inline constexpr int32_t kLonE6 = -127800;

}  // namespace clt::pktvec
