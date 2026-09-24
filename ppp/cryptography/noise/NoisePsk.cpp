#include <ppp/cryptography/noise/NoisePsk.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#else
#include <openssl/hmac.h>
#endif

#include <algorithm>
#include <cstring>
#include <utility>

namespace ppp::cryptography::noise {
namespace {

constexpr char ProtocolName[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
constexpr std::uint8_t PrologueDomain[] = {
    'o', 'p', 'e', 'n', 'p', 'p', 'p', '2', '-', 'n', 'o', 'i', 's', 'e',
    '-', 'h', 'a', 'n', 'd', 's', 'h', 'a', 'k', 'e',
};
constexpr std::uint8_t PrologueMethod[] = {
    'n', 'o', 'i', 's', 'e', '-', 'p', 's', 'k', '-', 'v', '1',
};
constexpr std::uint8_t ClientProofDomain[] = {
    'o', 'p', 'e', 'n', 'p', 'p', 'p', '2', '-', 'n', 'o', 'i', 's', 'e',
    '-', 'c', 'l', 'i', 'e', 'n', 't', '-', 's', 'u', 'c', 'c', 'e', 's', 's',
    '-', 'v', '1',
};
constexpr std::uint8_t BindingDomain[] = {
    'o', 'p', 'e', 'n', 'p', 'p', 'p', '2', '-', 'n', 'o', 'i', 's', 'e',
    '-', 'b', 'i', 'n', 'd', 'i', 'n', 'g', '-', 'v', '1',
};
constexpr char RetainedRootPurpose[] = "SessionResumeRetainedRootV1";
constexpr char CandidatePurpose[] = "SessionResumeCandidateV1";
constexpr char P2PWrapPurpose[] = "P2PWrapV1";

bool IsAllZero(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint8_t combined = 0;
    for (std::size_t i = 0; i < size; ++i) combined |= data[i];
    return combined == 0;
}

bool Sha256(const std::uint8_t* first, std::size_t first_size,
            const std::uint8_t* second, std::size_t second_size,
            Bytes32& output) noexcept {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    unsigned int output_size = 0;
    const bool ok = context != nullptr &&
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr) > 0 &&
        (first_size == 0 || EVP_DigestUpdate(context, first, first_size) > 0) &&
        (second_size == 0 || EVP_DigestUpdate(context, second, second_size) > 0) &&
        EVP_DigestFinal_ex(context, output.data(), &output_size) > 0 &&
        output_size == output.size();
    EVP_MD_CTX_free(context);
    if (!ok) OPENSSL_cleanse(output.data(), output.size());
    return ok;
}

struct HmacSegment final {
    const std::uint8_t* data;
    std::size_t size;
};

bool HmacSha256Segments(const std::uint8_t* key, std::size_t key_size,
                        const HmacSegment* segments, std::size_t segment_count,
                        Bytes32& output) noexcept {
    bool ok = key != nullptr && segments != nullptr;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MAC* mac = ok ? EVP_MAC_fetch(nullptr, "HMAC", nullptr) : nullptr;
    EVP_MAC_CTX* context = mac != nullptr ? EVP_MAC_CTX_new(mac) : nullptr;
    char digest[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end(),
    };
    ok = context != nullptr && EVP_MAC_init(context, key, key_size, parameters) > 0;
    for (std::size_t i = 0; ok && i < segment_count; ++i) {
        ok = segments[i].size == 0 ||
            (segments[i].data != nullptr &&
             EVP_MAC_update(context, segments[i].data, segments[i].size) > 0);
    }
    std::size_t output_size = 0;
    ok = ok && EVP_MAC_final(context, output.data(), &output_size, output.size()) > 0 &&
        output_size == output.size();
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
#else
    HMAC_CTX* context = ok ? HMAC_CTX_new() : nullptr;
    unsigned int output_size = 0;
    ok = context != nullptr &&
        HMAC_Init_ex(context, key, static_cast<int>(key_size), EVP_sha256(), nullptr) > 0;
    for (std::size_t i = 0; ok && i < segment_count; ++i) {
        ok = segments[i].size == 0 ||
            (segments[i].data != nullptr &&
             HMAC_Update(context, segments[i].data, segments[i].size) > 0);
    }
    ok = ok && HMAC_Final(context, output.data(), &output_size) > 0 &&
        output_size == output.size();
    HMAC_CTX_free(context);
#endif
    if (!ok) OPENSSL_cleanse(output.data(), output.size());
    return ok;
}

bool HmacSha256(const std::uint8_t* key, std::size_t key_size,
                const std::uint8_t* first, std::size_t first_size,
                const std::uint8_t* second, std::size_t second_size,
                const std::uint8_t* third, std::size_t third_size,
                Bytes32& output) noexcept {
    const HmacSegment segments[] = {
        {first, first_size}, {second, second_size}, {third, third_size},
    };
    return HmacSha256Segments(key, key_size, segments,
        sizeof(segments) / sizeof(segments[0]), output);
}

bool NoiseHkdf(const Bytes32& chaining_key,
               const std::uint8_t* input, std::size_t input_size,
               std::size_t output_count,
               Bytes32& output1, Bytes32& output2, Bytes32& output3) noexcept {
    Bytes32 temporary_key{};
    const std::uint8_t one = 1;
    const std::uint8_t two = 2;
    const std::uint8_t three = 3;
    const bool ok = (output_count == 2 || output_count == 3) &&
        HmacSha256(chaining_key.data(), chaining_key.size(),
            input, input_size, nullptr, 0, nullptr, 0, temporary_key) &&
        HmacSha256(temporary_key.data(), temporary_key.size(),
            &one, 1, nullptr, 0, nullptr, 0, output1) &&
        HmacSha256(temporary_key.data(), temporary_key.size(),
            output1.data(), output1.size(), &two, 1, nullptr, 0, output2) &&
        (output_count == 2 || HmacSha256(temporary_key.data(), temporary_key.size(),
            output2.data(), output2.size(), &three, 1, nullptr, 0, output3));
    OPENSSL_cleanse(temporary_key.data(), temporary_key.size());
    if (!ok) {
        OPENSSL_cleanse(output1.data(), output1.size());
        OPENSSL_cleanse(output2.data(), output2.size());
        OPENSSL_cleanse(output3.data(), output3.size());
    }
    return ok;
}

void BuildNoiseNonce(std::uint64_t value, std::uint8_t output[12]) noexcept {
    std::memset(output, 0, 12);
    for (std::size_t i = 0; i < 8; ++i) {
        output[4 + i] = static_cast<std::uint8_t>(value >> (i * 8));
    }
}

bool AeadEncryptEmpty(const Bytes32& key, std::uint64_t nonce,
                      const Bytes32& associated_data,
                      std::uint8_t tag[16]) noexcept {
    std::uint8_t encoded_nonce[12]{};
    std::uint8_t unused[1]{};
    int size = 0;
    BuildNoiseNonce(nonce, encoded_nonce);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    const bool ok = context != nullptr &&
        EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(sizeof(encoded_nonce)), nullptr) > 0 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), encoded_nonce) > 0 &&
        EVP_EncryptUpdate(context, nullptr, &size,
            associated_data.data(), static_cast<int>(associated_data.size())) > 0 &&
        EVP_EncryptFinal_ex(context, unused, &size) > 0 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag) > 0;
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(encoded_nonce, sizeof(encoded_nonce));
    OPENSSL_cleanse(unused, sizeof(unused));
    if (!ok) OPENSSL_cleanse(tag, 16);
    return ok;
}

bool AeadDecryptEmpty(const Bytes32& key, std::uint64_t nonce,
                      const Bytes32& associated_data,
                      const std::uint8_t tag[16]) noexcept {
    std::uint8_t encoded_nonce[12]{};
    std::uint8_t unused[1]{};
    int size = 0;
    BuildNoiseNonce(nonce, encoded_nonce);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    const bool ok = context != nullptr &&
        EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(sizeof(encoded_nonce)), nullptr) > 0 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), encoded_nonce) > 0 &&
        EVP_DecryptUpdate(context, nullptr, &size,
            associated_data.data(), static_cast<int>(associated_data.size())) > 0 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16,
            const_cast<std::uint8_t*>(tag)) > 0 &&
        EVP_DecryptFinal_ex(context, unused, &size) > 0;
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(encoded_nonce, sizeof(encoded_nonce));
    OPENSSL_cleanse(unused, sizeof(unused));
    return ok;
}

const char* PurposeLabel(BindingPurpose purpose) noexcept {
    switch (purpose) {
    case BindingPurpose::SessionResumeRetainedRootV1:
        return RetainedRootPurpose;
    case BindingPurpose::SessionResumeCandidateV1:
        return CandidatePurpose;
    case BindingPurpose::P2PWrapV1:
        return P2PWrapPurpose;
    default:
        return nullptr;
    }
}

}

Secret32::Secret32(Bytes32&& value) noexcept {
    Assign(std::move(value));
}

Secret32::~Secret32() noexcept {
    Clear();
}

Secret32::Secret32(Secret32&& other) noexcept {
    if (other.is_set_) {
        bytes_ = other.bytes_;
        is_set_ = true;
    }
    other.Clear();
}

Secret32& Secret32::operator=(Secret32&& other) noexcept {
    if (this != &other) {
        Clear();
        if (other.is_set_) {
            bytes_ = other.bytes_;
            is_set_ = true;
        }
        other.Clear();
    }
    return *this;
}

void Secret32::Assign(Bytes32&& value) noexcept {
    Clear();
    bytes_ = value;
    is_set_ = true;
    OPENSSL_cleanse(value.data(), value.size());
}

void Secret32::Clear() noexcept {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
    is_set_ = false;
}

bool Secret32::IsSet() const noexcept {
    return is_set_;
}

const std::uint8_t* Secret32::data() const noexcept {
    return bytes_.data();
}

std::size_t Secret32::size() const noexcept {
    return bytes_.size();
}

bool BuildCanonicalPrologue(Carrier carrier,
                            const SessionId& session_id,
                            const std::uint8_t* key_id,
                            std::size_t key_id_size,
                            std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if ((carrier != Carrier::Tcp && carrier != Carrier::WebSocket) ||
        key_id == nullptr || key_id_size == 0 || key_id_size > NoiseKeyIdMaxSize) {
        return false;
    }
    try {
        std::vector<std::uint8_t> built;
        built.reserve(1 + sizeof(PrologueDomain) + 1 + 2 + 1 + sizeof(PrologueMethod) +
            session_id.size() + 1 + key_id_size);
        built.push_back(static_cast<std::uint8_t>(sizeof(PrologueDomain)));
        built.insert(built.end(), std::begin(PrologueDomain), std::end(PrologueDomain));
        built.push_back(static_cast<std::uint8_t>(carrier));
        built.push_back(0);
        built.push_back(1);
        built.push_back(static_cast<std::uint8_t>(sizeof(PrologueMethod)));
        built.insert(built.end(), std::begin(PrologueMethod), std::end(PrologueMethod));
        built.insert(built.end(), session_id.begin(), session_id.end());
        built.push_back(static_cast<std::uint8_t>(key_id_size));
        built.insert(built.end(), key_id, key_id + key_id_size);
        output.swap(built);
        return true;
    } catch (...) {
        output.clear();
        return false;
    }
}

NoisePskHandshakeResult::~NoisePskHandshakeResult() noexcept {
    Clear();
}

NoisePskHandshakeResult::NoisePskHandshakeResult(
    NoisePskHandshakeResult&& other) noexcept {
    *this = std::move(other);
}

NoisePskHandshakeResult& NoisePskHandshakeResult::operator=(
    NoisePskHandshakeResult&& other) noexcept {
    if (this != &other) {
        Clear();
        exporter_ = std::move(other.exporter_);
        handshake_hash_ = other.handshake_hash_;
        valid_ = other.valid_;
        OPENSSL_cleanse(other.handshake_hash_.data(), other.handshake_hash_.size());
        other.valid_ = false;
    }
    return *this;
}

bool NoisePskHandshakeResult::IsValid() const noexcept {
    return valid_;
}

bool NoisePskHandshakeResult::GetHandshakeHash(Bytes32& output) const noexcept {
    output.fill(0);
    if (!valid_) return false;
    output = handshake_hash_;
    return true;
}

bool NoisePskHandshakeResult::GenerateClientSuccessConfirmationProof(
    ClientSuccessProof& output) const noexcept {
    output.fill(0);
    if (!valid_ || !exporter_.IsSet()) return false;
    Bytes32 proof{};
    const bool ok = HmacSha256(exporter_.data(), exporter_.size(),
        ClientProofDomain, sizeof(ClientProofDomain), handshake_hash_.data(),
        handshake_hash_.size(), nullptr, 0, proof);
    if (ok) output = proof;
    OPENSSL_cleanse(proof.data(), proof.size());
    return ok;
}

bool NoisePskHandshakeResult::VerifyClientSuccessConfirmationProof(
    const ClientSuccessProof& proof) const noexcept {
    ClientSuccessProof expected{};
    if (!GenerateClientSuccessConfirmationProof(expected)) return false;
    const bool ok = CRYPTO_memcmp(expected.data(), proof.data(), proof.size()) == 0;
    OPENSSL_cleanse(expected.data(), expected.size());
    return ok;
}

bool NoisePskHandshakeResult::DeriveBinding(
    BindingPurpose purpose, const std::uint8_t* binding_context,
    std::size_t context_length, Secret32& output) const noexcept {
    if (!valid_ || !exporter_.IsSet() || output.IsSet() ||
        binding_context == nullptr) {
        return false;
    }
    const char* label = PurposeLabel(purpose);
    const std::size_t required_context_length =
        purpose == BindingPurpose::P2PWrapV1 ? 113u : 16u;
    if (label == nullptr || context_length != required_context_length) return false;

    const std::size_t label_length = std::strlen(label);
    std::uint8_t lengths[24]{};
    const std::size_t field_lengths[] = {
        label_length, context_length, handshake_hash_.size(),
    };
    for (std::size_t field = 0; field < 3; ++field) {
        const std::uint64_t length = static_cast<std::uint64_t>(field_lengths[field]);
        for (std::size_t i = 0; i < 8; ++i) {
            lengths[field * 8 + i] =
                static_cast<std::uint8_t>(length >> ((7 - i) * 8));
        }
    }

    Bytes32 derived{};
    const HmacSegment segments[] = {
        {BindingDomain, sizeof(BindingDomain)},
        {lengths, 8},
        {reinterpret_cast<const std::uint8_t*>(label), label_length},
        {lengths + 8, 8},
        {binding_context, context_length},
        {lengths + 16, 8},
        {handshake_hash_.data(), handshake_hash_.size()},
    };
    const bool ok = HmacSha256Segments(exporter_.data(), exporter_.size(),
        segments, sizeof(segments) / sizeof(segments[0]), derived);
    OPENSSL_cleanse(lengths, sizeof(lengths));
    if (ok) output.Assign(std::move(derived));
    OPENSSL_cleanse(derived.data(), derived.size());
    return ok;
}

bool NoisePskHandshakeResult::TakeExporterSecret(Secret32& output) noexcept {
    if (!valid_ || !exporter_.IsSet() || output.IsSet()) return false;
    output = std::move(exporter_);
    return true;
}

void NoisePskHandshakeResult::Clear() noexcept {
    exporter_.Clear();
    OPENSSL_cleanse(handshake_hash_.data(), handshake_hash_.size());
    valid_ = false;
}

NoisePskHandshake::NoisePskHandshake(
    HandshakeRole role, Secret32&& psk,
    const std::vector<std::uint8_t>& prologue) noexcept
    : role_(role), psk_(std::move(psk)) {
    if ((role_ != HandshakeRole::NetworkClientInitiator &&
         role_ != HandshakeRole::NetworkServerResponder) ||
        !psk_.IsSet() || !Initialize(prologue)) {
        Fail();
    }
}

NoisePskHandshake::~NoisePskHandshake() noexcept {
    Clear();
}

NoisePskHandshake::NoisePskHandshake(NoisePskHandshake&& other) noexcept {
    *this = std::move(other);
}

NoisePskHandshake& NoisePskHandshake::operator=(NoisePskHandshake&& other) noexcept {
    if (this != &other) {
        Clear();
        role_ = other.role_;
        state_ = other.state_;
        psk_ = std::move(other.psk_);
        deterministic_private_key_ = std::move(other.deterministic_private_key_);
        chaining_key_ = other.chaining_key_;
        handshake_hash_ = other.handshake_hash_;
        cipher_key_ = other.cipher_key_;
        ephemeral_private_ = other.ephemeral_private_;
        ephemeral_public_ = other.ephemeral_public_;
        remote_ephemeral_public_ = other.remote_ephemeral_public_;
        exporter_ = std::move(other.exporter_);
        nonce_ = other.nonce_;
        has_cipher_key_ = other.has_cipher_key_;
        has_ephemeral_ = other.has_ephemeral_;
        has_remote_ephemeral_ = other.has_remote_ephemeral_;
        other.Clear();
    }
    return *this;
}

bool NoisePskHandshake::IsValid() const noexcept {
    return state_ != State::Invalid && state_ != State::Failed;
}

bool NoisePskHandshake::IsComplete() const noexcept {
    return state_ == State::Complete;
}

bool NoisePskHandshake::SetDeterministicEphemeralPrivateKeyForTesting(
    Secret32&& private_key) noexcept {
    if (state_ != State::Initial || deterministic_private_key_.IsSet() ||
        !private_key.IsSet() || IsAllZero(private_key.data(), private_key.size())) {
        return false;
    }
    deterministic_private_key_ = std::move(private_key);
    return true;
}

bool NoisePskHandshake::Initialize(
    const std::vector<std::uint8_t>& prologue) noexcept {
    Bytes32 initialized{};
    const auto* name = reinterpret_cast<const std::uint8_t*>(ProtocolName);
    if (!Sha256(name, sizeof(ProtocolName) - 1, nullptr, 0, initialized)) return false;
    handshake_hash_ = initialized;
    chaining_key_ = initialized;
    OPENSSL_cleanse(initialized.data(), initialized.size());
    has_cipher_key_ = false;
    nonce_ = 0;
    if (!MixHash(prologue.data(), prologue.size())) return false;
    state_ = State::Initial;
    return true;
}

bool NoisePskHandshake::GenerateEphemeral() noexcept {
    if (has_ephemeral_) return false;
    EVP_PKEY_CTX* key_context = nullptr;
    EVP_PKEY* key = nullptr;
    if (deterministic_private_key_.IsSet()) {
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            deterministic_private_key_.data(), deterministic_private_key_.size());
        deterministic_private_key_.Clear();
    } else {
        key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (key_context != nullptr && EVP_PKEY_keygen_init(key_context) > 0 &&
            EVP_PKEY_keygen(key_context, &key) <= 0) {
            EVP_PKEY_free(key);
            key = nullptr;
        }
    }

    std::size_t private_size = ephemeral_private_.size();
    std::size_t public_size = ephemeral_public_.size();
    const bool ok = key != nullptr &&
        EVP_PKEY_get_raw_private_key(key, ephemeral_private_.data(), &private_size) > 0 &&
        private_size == ephemeral_private_.size() &&
        EVP_PKEY_get_raw_public_key(key, ephemeral_public_.data(), &public_size) > 0 &&
        public_size == ephemeral_public_.size();
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    if (!ok) {
        OPENSSL_cleanse(ephemeral_private_.data(), ephemeral_private_.size());
        ephemeral_public_.fill(0);
        return false;
    }
    has_ephemeral_ = true;
    return true;
}

bool NoisePskHandshake::ProcessPsk() noexcept {
    if (!psk_.IsSet()) return false;
    const bool ok = MixKeyAndHash(psk_.data(), psk_.size());
    psk_.Clear();
    return ok;
}

bool NoisePskHandshake::MixHash(
    const std::uint8_t* data, std::size_t size) noexcept {
    if (size != 0 && data == nullptr) return false;
    Bytes32 mixed{};
    if (!Sha256(handshake_hash_.data(), handshake_hash_.size(), data, size, mixed)) {
        return false;
    }
    handshake_hash_ = mixed;
    OPENSSL_cleanse(mixed.data(), mixed.size());
    return true;
}

bool NoisePskHandshake::MixKey(
    const std::uint8_t* input, std::size_t size) noexcept {
    if (size != 0 && input == nullptr) return false;
    Bytes32 first{};
    Bytes32 second{};
    Bytes32 unused{};
    const bool ok = NoiseHkdf(chaining_key_, input, size, 2, first, second, unused);
    if (ok) {
        chaining_key_ = first;
        cipher_key_ = second;
        nonce_ = 0;
        has_cipher_key_ = true;
    }
    OPENSSL_cleanse(first.data(), first.size());
    OPENSSL_cleanse(second.data(), second.size());
    OPENSSL_cleanse(unused.data(), unused.size());
    return ok;
}

bool NoisePskHandshake::MixKeyAndHash(
    const std::uint8_t* input, std::size_t size) noexcept {
    if (size != 0 && input == nullptr) return false;
    Bytes32 first{};
    Bytes32 second{};
    Bytes32 third{};
    bool ok = NoiseHkdf(chaining_key_, input, size, 3, first, second, third);
    if (ok) {
        chaining_key_ = first;
        ok = MixHash(second.data(), second.size());
    }
    if (ok) {
        cipher_key_ = third;
        nonce_ = 0;
        has_cipher_key_ = true;
    }
    OPENSSL_cleanse(first.data(), first.size());
    OPENSSL_cleanse(second.data(), second.size());
    OPENSSL_cleanse(third.data(), third.size());
    return ok;
}

bool NoisePskHandshake::EncryptEmpty(std::uint8_t* tag) noexcept {
    if (!has_cipher_key_ || tag == nullptr || nonce_ == UINT64_MAX) return false;
    if (!AeadEncryptEmpty(cipher_key_, nonce_, handshake_hash_, tag)) return false;
    ++nonce_;
    return MixHash(tag, 16);
}

bool NoisePskHandshake::DecryptEmpty(const std::uint8_t* tag) noexcept {
    if (!has_cipher_key_ || tag == nullptr || nonce_ == UINT64_MAX) return false;
    if (!AeadDecryptEmpty(cipher_key_, nonce_, handshake_hash_, tag)) return false;
    ++nonce_;
    return MixHash(tag, 16);
}

bool NoisePskHandshake::Dh(
    const Bytes32& remote_public, Bytes32& output) noexcept {
    OPENSSL_cleanse(output.data(), output.size());
    if (!has_ephemeral_ || IsAllZero(remote_public.data(), remote_public.size())) return false;
    EVP_PKEY* private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
        ephemeral_private_.data(), ephemeral_private_.size());
    EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
        remote_public.data(), remote_public.size());
    EVP_PKEY_CTX* context = private_key == nullptr ? nullptr : EVP_PKEY_CTX_new(private_key, nullptr);
    std::size_t output_size = output.size();
    const bool ok = context != nullptr && public_key != nullptr &&
        EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_derive_set_peer(context, public_key) > 0 &&
        EVP_PKEY_derive(context, output.data(), &output_size) > 0 &&
        output_size == output.size() && !IsAllZero(output.data(), output.size());
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    if (!ok) OPENSSL_cleanse(output.data(), output.size());
    return ok;
}

bool NoisePskHandshake::WriteMessage1(
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (role_ != HandshakeRole::NetworkClientInitiator || state_ != State::Initial) {
        return false;
    }
    std::array<std::uint8_t, 16> tag{};
    if (!ProcessPsk() || !GenerateEphemeral() ||
        !MixHash(ephemeral_public_.data(), ephemeral_public_.size()) ||
        !MixKey(ephemeral_public_.data(), ephemeral_public_.size()) ||
        !EncryptEmpty(tag.data())) {
        OPENSSL_cleanse(tag.data(), tag.size());
        return Fail();
    }
    try {
        output.reserve(NoiseHandshakeMessageSize);
        output.insert(output.end(), ephemeral_public_.begin(), ephemeral_public_.end());
        output.insert(output.end(), tag.begin(), tag.end());
    } catch (...) {
        OPENSSL_cleanse(tag.data(), tag.size());
        output.clear();
        return Fail();
    }
    OPENSSL_cleanse(tag.data(), tag.size());
    state_ = State::InitiatorAwaitingMessage2;
    return true;
}

bool NoisePskHandshake::ReadMessage1(
    const std::uint8_t* message, std::size_t message_size) noexcept {
    if (role_ != HandshakeRole::NetworkServerResponder || state_ != State::Initial) {
        return false;
    }
    if (message == nullptr || message_size != NoiseHandshakeMessageSize) return Fail();
    std::copy(message, message + remote_ephemeral_public_.size(),
        remote_ephemeral_public_.begin());
    if (IsAllZero(remote_ephemeral_public_.data(), remote_ephemeral_public_.size())) {
        return Fail();
    }
    has_remote_ephemeral_ = true;
    if (!ProcessPsk() ||
        !MixHash(remote_ephemeral_public_.data(), remote_ephemeral_public_.size()) ||
        !MixKey(remote_ephemeral_public_.data(), remote_ephemeral_public_.size()) ||
        !DecryptEmpty(message + remote_ephemeral_public_.size())) {
        return Fail();
    }
    state_ = State::ResponderReadyForMessage2;
    return true;
}

bool NoisePskHandshake::WriteMessage2(
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (role_ != HandshakeRole::NetworkServerResponder ||
        state_ != State::ResponderReadyForMessage2 || !has_remote_ephemeral_) {
        return false;
    }
    Bytes32 shared{};
    std::array<std::uint8_t, 16> tag{};
    if (!GenerateEphemeral() ||
        !MixHash(ephemeral_public_.data(), ephemeral_public_.size()) ||
        !MixKey(ephemeral_public_.data(), ephemeral_public_.size()) ||
        !Dh(remote_ephemeral_public_, shared) ||
        !MixKey(shared.data(), shared.size()) || !EncryptEmpty(tag.data())) {
        OPENSSL_cleanse(shared.data(), shared.size());
        OPENSSL_cleanse(tag.data(), tag.size());
        return Fail();
    }
    OPENSSL_cleanse(shared.data(), shared.size());
    try {
        output.reserve(NoiseHandshakeMessageSize);
        output.insert(output.end(), ephemeral_public_.begin(), ephemeral_public_.end());
        output.insert(output.end(), tag.begin(), tag.end());
    } catch (...) {
        OPENSSL_cleanse(tag.data(), tag.size());
        output.clear();
        return Fail();
    }
    OPENSSL_cleanse(tag.data(), tag.size());
    if (!Finish()) {
        output.clear();
        return Fail();
    }
    return true;
}

bool NoisePskHandshake::ReadMessage2(
    const std::uint8_t* message, std::size_t message_size) noexcept {
    if (role_ != HandshakeRole::NetworkClientInitiator ||
        state_ != State::InitiatorAwaitingMessage2) {
        return false;
    }
    if (message == nullptr || message_size != NoiseHandshakeMessageSize) return Fail();
    std::copy(message, message + remote_ephemeral_public_.size(),
        remote_ephemeral_public_.begin());
    has_remote_ephemeral_ = true;
    Bytes32 shared{};
    if (!MixHash(remote_ephemeral_public_.data(), remote_ephemeral_public_.size()) ||
        !MixKey(remote_ephemeral_public_.data(), remote_ephemeral_public_.size()) ||
        !Dh(remote_ephemeral_public_, shared) || !MixKey(shared.data(), shared.size()) ||
        !DecryptEmpty(message + remote_ephemeral_public_.size())) {
        OPENSSL_cleanse(shared.data(), shared.size());
        return Fail();
    }
    OPENSSL_cleanse(shared.data(), shared.size());
    if (!Finish()) return Fail();
    return true;
}

bool NoisePskHandshake::Finish() noexcept {
    Bytes32 directional1{};
    Bytes32 directional2{};
    Bytes32 exporter{};
    const bool ok = NoiseHkdf(chaining_key_, nullptr, 0, 3,
        directional1, directional2, exporter);
    if (ok) exporter_.Assign(std::move(exporter));
    OPENSSL_cleanse(directional1.data(), directional1.size());
    OPENSSL_cleanse(directional2.data(), directional2.size());
    OPENSSL_cleanse(exporter.data(), exporter.size());
    if (!ok) return false;
    state_ = State::Complete;
    ClearSecrets();
    return true;
}

bool NoisePskHandshake::TakeResult(NoisePskHandshakeResult& output) noexcept {
    if (state_ != State::Complete || !exporter_.IsSet() || output.IsValid()) return false;
    output.Clear();
    output.exporter_ = std::move(exporter_);
    output.handshake_hash_ = handshake_hash_;
    output.valid_ = true;
    OPENSSL_cleanse(handshake_hash_.data(), handshake_hash_.size());
    state_ = State::ResultTaken;
    return true;
}

void NoisePskHandshake::ClearSecrets() noexcept {
    psk_.Clear();
    deterministic_private_key_.Clear();
    OPENSSL_cleanse(chaining_key_.data(), chaining_key_.size());
    OPENSSL_cleanse(cipher_key_.data(), cipher_key_.size());
    OPENSSL_cleanse(ephemeral_private_.data(), ephemeral_private_.size());
    ephemeral_public_.fill(0);
    remote_ephemeral_public_.fill(0);
    nonce_ = 0;
    has_cipher_key_ = false;
    has_ephemeral_ = false;
    has_remote_ephemeral_ = false;
}

bool NoisePskHandshake::Fail() noexcept {
    ClearSecrets();
    exporter_.Clear();
    OPENSSL_cleanse(handshake_hash_.data(), handshake_hash_.size());
    state_ = State::Failed;
    return false;
}

void NoisePskHandshake::Clear() noexcept {
    ClearSecrets();
    exporter_.Clear();
    OPENSSL_cleanse(handshake_hash_.data(), handshake_hash_.size());
    state_ = State::Invalid;
}

}
