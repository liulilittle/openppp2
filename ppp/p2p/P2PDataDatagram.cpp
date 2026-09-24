#include <ppp/p2p/P2PDataDatagram.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <limits>

namespace ppp::p2p {
namespace {

constexpr std::uint8_t Version = 1;
constexpr std::uint8_t DataType = 5;

bool ValidHeader(const P2PDataPacketHeader& header) noexcept {
    return header.sender_role <= 1 && header.receiver_role <= 1 &&
        header.sender_role != header.receiver_role &&
        header.direction == header.sender_role &&
        header.payload_length >= 1 &&
        header.payload_length <= P2PDataPacketHeader::MaxPayloadSize &&
        header.offer_hash != std::array<std::uint8_t, 32>{} &&
        header.connection_epoch != std::array<std::uint8_t, 16>{};
}

void SerializeHeader(const P2PDataPacketHeader& header,
    std::uint8_t* output) noexcept {
    output[0] = Version;
    output[1] = DataType;
    output[2] = 0;
    output[3] = 0;
    std::copy(header.offer_hash.begin(), header.offer_hash.end(), output + 4);
    output[36] = header.sender_role;
    output[37] = header.receiver_role;
    output[38] = header.direction;
    output[39] = 0;
    std::copy(header.connection_epoch.begin(),
        header.connection_epoch.end(), output + 40);
    output[56] = static_cast<std::uint8_t>(header.sequence >> 24);
    output[57] = static_cast<std::uint8_t>(header.sequence >> 16);
    output[58] = static_cast<std::uint8_t>(header.sequence >> 8);
    output[59] = static_cast<std::uint8_t>(header.sequence);
    output[60] = static_cast<std::uint8_t>(header.payload_length >> 8);
    output[61] = static_cast<std::uint8_t>(header.payload_length);
}

bool MatchesExpected(const P2PDataPacketHeader& actual,
    const P2PDataPacketHeader& expected) noexcept {
    return actual.offer_hash == expected.offer_hash &&
        actual.sender_role == expected.sender_role &&
        actual.receiver_role == expected.receiver_role &&
        actual.direction == expected.direction &&
        actual.connection_epoch == expected.connection_epoch &&
        actual.sequence == expected.sequence;
}

}

bool ParseP2PDataPacketHeader(
    const std::vector<std::uint8_t>& datagram,
    P2PDataPacketHeader& output) noexcept {
    if (datagram.size() <
            P2PDataPacketHeader::HeaderSize + P2PDataPacketHeader::TagSize ||
        datagram[0] != Version || datagram[1] != DataType ||
        datagram[2] != 0 || datagram[3] != 0 || datagram[39] != 0) {
        return false;
    }

    P2PDataPacketHeader parsed;
    std::copy(datagram.begin() + 4, datagram.begin() + 36,
        parsed.offer_hash.begin());
    parsed.sender_role = datagram[36];
    parsed.receiver_role = datagram[37];
    parsed.direction = datagram[38];
    std::copy(datagram.begin() + 40, datagram.begin() + 56,
        parsed.connection_epoch.begin());
    parsed.sequence = static_cast<std::uint32_t>(datagram[56]) << 24 |
        static_cast<std::uint32_t>(datagram[57]) << 16 |
        static_cast<std::uint32_t>(datagram[58]) << 8 |
        static_cast<std::uint32_t>(datagram[59]);
    parsed.payload_length = static_cast<std::uint16_t>(datagram[60]) << 8 |
        static_cast<std::uint16_t>(datagram[61]);
    const std::size_t expected_size = P2PDataPacketHeader::HeaderSize +
        parsed.payload_length + P2PDataPacketHeader::TagSize;
    if (!ValidHeader(parsed) || datagram.size() != expected_size) {
        return false;
    }

    output = parsed;
    return true;
}

bool SealP2PDataDatagram(
    const P2PDataPacketHeader& header,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 12>& nonce,
    const std::uint8_t* payload,
    std::size_t payload_length,
    std::vector<std::uint8_t>& output) noexcept {
    if (!payload || payload_length == 0 ||
        payload_length > P2PDataPacketHeader::MaxPayloadSize ||
        payload_length > std::numeric_limits<std::uint16_t>::max()) {
        return false;
    }

    auto wire_header = header;
    wire_header.payload_length = static_cast<std::uint16_t>(payload_length);
    if (!ValidHeader(wire_header)) return false;

    std::vector<std::uint8_t> datagram;
    try {
        datagram.resize(P2PDataPacketHeader::HeaderSize + payload_length +
            P2PDataPacketHeader::TagSize);
    }
    catch (...) {
        return false;
    }
    SerializeHeader(wire_header, datagram.data());

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) return false;
    bool success = false;
    do {
        if (EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(),
                nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(context, nullptr, nullptr,
                key.data(), nonce.data()) != 1) {
            break;
        }
        int length = 0;
        if (EVP_EncryptUpdate(context, nullptr, &length, datagram.data(),
                static_cast<int>(P2PDataPacketHeader::HeaderSize)) != 1 ||
            EVP_EncryptUpdate(context,
                datagram.data() + P2PDataPacketHeader::HeaderSize,
                &length, payload, static_cast<int>(payload_length)) != 1) {
            break;
        }
        int total = length;
        if (EVP_EncryptFinal_ex(context,
                datagram.data() + P2PDataPacketHeader::HeaderSize + total,
                &length) != 1) {
            break;
        }
        total += length;
        if (total != static_cast<int>(payload_length) ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG,
                static_cast<int>(P2PDataPacketHeader::TagSize),
                datagram.data() + P2PDataPacketHeader::HeaderSize +
                    payload_length) != 1) {
            break;
        }
        success = true;
    } while (false);
    EVP_CIPHER_CTX_free(context);
    if (!success) return false;

    output.swap(datagram);
    return true;
}

bool OpenP2PDataDatagram(
    const std::vector<std::uint8_t>& datagram,
    const P2PDataPacketHeader& expected,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 12>& nonce,
    std::vector<std::uint8_t>& output) noexcept {
    P2PDataPacketHeader parsed;
    if (!ParseP2PDataPacketHeader(datagram, parsed) ||
        !MatchesExpected(parsed, expected)) {
        return false;
    }

    std::vector<std::uint8_t> plaintext;
    try {
        plaintext.resize(parsed.payload_length);
    }
    catch (...) {
        return false;
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) return false;
    bool success = false;
    do {
        if (EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(),
                nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(nonce.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(context, nullptr, nullptr,
                key.data(), nonce.data()) != 1) {
            break;
        }
        int length = 0;
        if (EVP_DecryptUpdate(context, nullptr, &length, datagram.data(),
                static_cast<int>(P2PDataPacketHeader::HeaderSize)) != 1 ||
            EVP_DecryptUpdate(context, plaintext.data(), &length,
                datagram.data() + P2PDataPacketHeader::HeaderSize,
                parsed.payload_length) != 1) {
            break;
        }
        int total = length;
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(P2PDataPacketHeader::TagSize),
                const_cast<std::uint8_t*>(datagram.data() +
                    P2PDataPacketHeader::HeaderSize + parsed.payload_length)) != 1 ||
            EVP_DecryptFinal_ex(context, plaintext.data() + total, &length) != 1) {
            break;
        }
        total += length;
        if (total != parsed.payload_length) break;
        success = true;
    } while (false);
    EVP_CIPHER_CTX_free(context);
    if (!success) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }

    output.swap(plaintext);
    return true;
}

}
