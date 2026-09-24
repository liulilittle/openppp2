#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ppp::cryptography::noise {

inline constexpr std::size_t NoisePskSize = 32;
inline constexpr std::size_t NoiseSessionIdSize = 16;
inline constexpr std::size_t NoiseKeyIdMaxSize = 64;
inline constexpr std::size_t NoiseHandshakeMessageSize = 48;
inline constexpr std::size_t NoiseProofSize = 32;

using Bytes32 = std::array<std::uint8_t, 32>;
using SessionId = std::array<std::uint8_t, NoiseSessionIdSize>;
using ClientSuccessProof = std::array<std::uint8_t, NoiseProofSize>;

/** A fixed-size move-only secret which is cleansed on clear and destruction. */
class Secret32 final {
public:
    Secret32() noexcept = default;
    explicit Secret32(Bytes32&& value) noexcept;
    ~Secret32() noexcept;

    Secret32(const Secret32&) = delete;
    Secret32& operator=(const Secret32&) = delete;
    Secret32(Secret32&& other) noexcept;
    Secret32& operator=(Secret32&& other) noexcept;

    /** Consumes and cleanses the source array. */
    void Assign(Bytes32&& value) noexcept;
    void Clear() noexcept;
    bool IsSet() const noexcept;
    const std::uint8_t* data() const noexcept;
    std::size_t size() const noexcept;

private:
    friend class NoisePskHandshake;
    friend class NoisePskHandshakeResult;

    Bytes32 bytes_{};
    bool is_set_ = false;
};

enum class Carrier : std::uint8_t {
    Tcp = 1,
    WebSocket = 2,
};

enum class HandshakeRole : std::uint8_t {
    NetworkClientInitiator = 1,
    NetworkServerResponder = 2,
};

enum class BindingPurpose : std::uint8_t {
    SessionResumeRetainedRootV1 = 1,
    SessionResumeCandidateV1 = 2,
    P2PWrapV1 = 3,
};

/** Builds the version-1 canonical binary prologue. Key identifiers are 1..64 bytes. */
bool BuildCanonicalPrologue(Carrier carrier,
                            const SessionId& session_id,
                            const std::uint8_t* key_id,
                            std::size_t key_id_size,
                            std::vector<std::uint8_t>& output) noexcept;

/** Completed handshake material. The handshake hash is public transcript state. */
class NoisePskHandshakeResult final {
public:
    NoisePskHandshakeResult() noexcept = default;
    ~NoisePskHandshakeResult() noexcept;

    NoisePskHandshakeResult(const NoisePskHandshakeResult&) = delete;
    NoisePskHandshakeResult& operator=(const NoisePskHandshakeResult&) = delete;
    NoisePskHandshakeResult(NoisePskHandshakeResult&& other) noexcept;
    NoisePskHandshakeResult& operator=(NoisePskHandshakeResult&& other) noexcept;

    bool IsValid() const noexcept;
    bool GetHandshakeHash(Bytes32& output) const noexcept;
    bool GenerateClientSuccessConfirmationProof(ClientSuccessProof& output) const noexcept;
    bool VerifyClientSuccessConfirmationProof(const ClientSuccessProof& proof) const noexcept;
    bool DeriveBinding(BindingPurpose purpose,
                       const std::uint8_t* context,
                       std::size_t context_length,
                       Secret32& output) const noexcept;
    bool TakeExporterSecret(Secret32& output) noexcept;
    void Clear() noexcept;

private:
    friend class NoisePskHandshake;

    Secret32 exporter_;
    Bytes32 handshake_hash_{};
    bool valid_ = false;
};

/** Strict Noise_NNpsk0_25519_ChaChaPoly_SHA256 two-message handshake. */
class NoisePskHandshake final {
public:
    NoisePskHandshake(HandshakeRole role,
                      Secret32&& psk,
                      const std::vector<std::uint8_t>& prologue) noexcept;
    ~NoisePskHandshake() noexcept;

    NoisePskHandshake(const NoisePskHandshake&) = delete;
    NoisePskHandshake& operator=(const NoisePskHandshake&) = delete;
    NoisePskHandshake(NoisePskHandshake&& other) noexcept;
    NoisePskHandshake& operator=(NoisePskHandshake&& other) noexcept;

    bool IsValid() const noexcept;
    bool IsComplete() const noexcept;

    /** Test-only hook. Production leaves this unset and uses EVP key generation. */
    bool SetDeterministicEphemeralPrivateKeyForTesting(Secret32&& private_key) noexcept;

    bool WriteMessage1(std::vector<std::uint8_t>& output) noexcept;
    bool ReadMessage1(const std::uint8_t* message, std::size_t message_size) noexcept;
    bool WriteMessage2(std::vector<std::uint8_t>& output) noexcept;
    bool ReadMessage2(const std::uint8_t* message, std::size_t message_size) noexcept;

    bool TakeResult(NoisePskHandshakeResult& output) noexcept;
    void Clear() noexcept;

private:
    enum class State : std::uint8_t {
        Invalid,
        Initial,
        InitiatorAwaitingMessage2,
        ResponderReadyForMessage2,
        Complete,
        ResultTaken,
        Failed,
    };

    bool Initialize(const std::vector<std::uint8_t>& prologue) noexcept;
    bool GenerateEphemeral() noexcept;
    bool ProcessPsk() noexcept;
    bool MixHash(const std::uint8_t* data, std::size_t size) noexcept;
    bool MixKey(const std::uint8_t* input, std::size_t size) noexcept;
    bool MixKeyAndHash(const std::uint8_t* input, std::size_t size) noexcept;
    bool EncryptEmpty(std::uint8_t* tag) noexcept;
    bool DecryptEmpty(const std::uint8_t* tag) noexcept;
    bool Dh(const Bytes32& remote_public, Bytes32& output) noexcept;
    bool Finish() noexcept;
    bool Fail() noexcept;
    void ClearSecrets() noexcept;

    HandshakeRole role_ = HandshakeRole::NetworkClientInitiator;
    State state_ = State::Invalid;
    Secret32 psk_;
    Secret32 deterministic_private_key_;
    Bytes32 chaining_key_{};
    Bytes32 handshake_hash_{};
    Bytes32 cipher_key_{};
    Bytes32 ephemeral_private_{};
    Bytes32 ephemeral_public_{};
    Bytes32 remote_ephemeral_public_{};
    Secret32 exporter_;
    std::uint64_t nonce_ = 0;
    bool has_cipher_key_ = false;
    bool has_ephemeral_ = false;
    bool has_remote_ephemeral_ = false;
};

}
