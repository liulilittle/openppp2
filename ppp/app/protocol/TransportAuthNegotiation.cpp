#include <ppp/app/protocol/TransportAuthNegotiation.h>

#include <openssl/crypto.h>

#include <array>
#include <cstring>
#include <utility>
#include <vector>

namespace ppp::app::protocol {
namespace {

namespace noise = ppp::cryptography::noise;
namespace configurations = ppp::configurations;

bool IsSupportedCarrierContext(const TransportAuthNegotiationContext& context) noexcept {
    return context.carrier == TransportAuthCarrier::Tcp ||
        context.carrier == TransportAuthCarrier::WebSocket;
}

template <typename String>
bool IsCanonicalToken(const String& value) noexcept {
    if (value.size() != TransportAuthTokenHexLength) return false;
    for (const char ch : value) {
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
    }
    return true;
}

bool IsSupportedInitiatorContext(const TransportAuthNegotiationContext& context) noexcept {
    return IsSupportedCarrierContext(context) && IsCanonicalToken(context.token);
}

bool BuildPrologue(const TransportAuthNegotiationContext& context,
                   const std::string& key_id,
                   std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (!IsSupportedInitiatorContext(context) || key_id.empty()) return false;

    const noise::Carrier carrier = context.carrier == TransportAuthCarrier::Tcp
        ? noise::Carrier::Tcp
        : noise::Carrier::WebSocket;
    if (!noise::BuildCanonicalPrologue(carrier, context.session_id,
            reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), output)) {
        return false;
    }

    try {
        // Canonical transport-auth extension: version, uint16-be token length, token bytes.
        output.push_back(1);
        output.push_back(static_cast<std::uint8_t>(context.token.size() >> 8));
        output.push_back(static_cast<std::uint8_t>(context.token.size()));
        output.insert(output.end(), context.token.begin(), context.token.end());
        return true;
    }
    catch (...) {
        output.clear();
        return false;
    }
}

bool CopySecret(const configurations::TransportAuthKeyringSnapshot::Key& key,
                noise::Secret32& output) noexcept {
    noise::Bytes32 copy{};
    static_assert(configurations::TransportAuthSecret::Size == noise::NoisePskSize,
        "transport-auth and Noise PSKs must have the same fixed size");
    std::memcpy(copy.data(), key.secret.data(), copy.size());
    output.Assign(std::move(copy));
    OPENSSL_cleanse(copy.data(), copy.size());
    return output.IsSet();
}

template <typename String>
bool HexEncode(const std::uint8_t* input, std::size_t size, String& output) noexcept {
    static constexpr char Hex[] = "0123456789abcdef";
    output.clear();
    if (input == nullptr || size == 0) return false;
    try {
        String encoded(size * 2, '0');
        for (std::size_t i = 0; i < size; ++i) {
            encoded[i * 2] = Hex[input[i] >> 4];
            encoded[i * 2 + 1] = Hex[input[i] & 0x0f];
        }
        output.swap(encoded);
        return true;
    }
    catch (...) {
        output.clear();
        return false;
    }
}

std::uint8_t DecodeNibble(char value) noexcept {
    return value <= '9' ? static_cast<std::uint8_t>(value - '0')
                        : static_cast<std::uint8_t>(value - 'a' + 10);
}

template <std::size_t N, typename String>
bool HexDecode(const String& input, std::array<std::uint8_t, N>& output) noexcept {
    output.fill(0);
    if (input.size() != N * 2) return false;
    for (std::size_t i = 0; i < input.size(); ++i) {
        const char value = input[i];
        if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) {
            return false;
        }
    }
    for (std::size_t i = 0; i < N; ++i) {
        output[i] = static_cast<std::uint8_t>(
            (DecodeNibble(input[i * 2]) << 4) | DecodeNibble(input[i * 2 + 1]));
    }
    return true;
}

template <typename LeftString, typename RightString>
bool EqualText(const LeftString& left, const RightString& right) noexcept {
    return left.size() == right.size() &&
        std::memcmp(left.data(), right.data(), left.size()) == 0;
}

template <typename String>
bool IsCanonicalKeyId(const String& value) noexcept {
    if (value.empty() || value.size() > TransportAuthControl::MaximumKeyIdLength ||
        !((value.front() >= 'a' && value.front() <= 'z') ||
          (value.front() >= '0' && value.front() <= '9'))) {
        return false;
    }
    for (const char ch : value) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '_' || ch == '-')) {
            return false;
        }
    }
    return true;
}

bool IsExactAdvertisement(const TransportAuthControl& control) noexcept {
    return control.version == TransportAuthControl::ProtocolVersion &&
        control.action == TransportAuthAction::Advertise &&
        control.methods.size() == 1 &&
        control.methods.front() == TransportAuthNoisePskV1Method &&
        control.method == TransportAuthNoisePskV1Method &&
        IsCanonicalKeyId(control.key_id) && IsCanonicalToken(control.token) &&
        control.sequence == 1 &&
        control.message.size() == noise::NoiseHandshakeMessageSize * 2 &&
        control.proof.empty() && control.reason.empty();
}

bool IsExactSelection(const TransportAuthControl& control,
                      const std::string& key_id,
                      const std::string& token) noexcept {
    return control.version == TransportAuthControl::ProtocolVersion &&
        control.action == TransportAuthAction::Select &&
        control.methods.empty() &&
        control.method == TransportAuthNoisePskV1Method &&
        EqualText(control.key_id, key_id) &&
        IsCanonicalToken(control.token) && EqualText(control.token, token) &&
        control.sequence == 2 &&
        control.message.size() == noise::NoiseHandshakeMessageSize * 2 &&
        control.proof.empty() && control.reason.empty();
}

bool IsExactSuccess(const TransportAuthControl& control,
                    const std::string& key_id,
                    const std::string& token,
                    bool proof_required) noexcept {
    return control.version == TransportAuthControl::ProtocolVersion &&
        control.action == TransportAuthAction::Success &&
        control.methods.empty() &&
        control.method == TransportAuthNoisePskV1Method &&
        EqualText(control.key_id, key_id) &&
        IsCanonicalToken(control.token) && EqualText(control.token, token) &&
        control.sequence == 0 && control.message.empty() && control.reason.empty() &&
        (proof_required ? control.proof.size() == noise::NoiseProofSize * 2
                        : control.proof.empty());
}

void MakeReject(TransportAuthControl& output, const std::string* token) noexcept {
    output = TransportAuthControl{};
    output.action = TransportAuthAction::Reject;
    output.reason = "authentication-failed";
    if (token != nullptr) output.token.assign(token->data(), token->size());
}

}

TransportAuthInitiator::TransportAuthInitiator(
    std::shared_ptr<const configurations::TransportAuthKeyringSnapshot> keyring,
    const TransportAuthNegotiationContext& context)
    : keyring_(std::move(keyring)), context_(context) {
    if (!keyring_ || !keyring_->active() || !IsSupportedInitiatorContext(context_) ||
        !IsCanonicalKeyId(keyring_->active()->id)) {
        return;
    }
    key_id_ = keyring_->active()->id;
    state_ = State::Ready;
}

bool TransportAuthInitiator::CreateAdvertisement(TransportAuthControl& output) noexcept {
    output = TransportAuthControl{};
    if (state_ != State::Ready || !keyring_) return Fail();

    const configurations::TransportAuthKeyringSnapshot::Key* key = keyring_->active();
    if (key == nullptr || key->state != configurations::TransportAuthKeyState::Active ||
        key->id != key_id_) {
        return Fail();
    }

    std::vector<std::uint8_t> prologue;
    noise::Secret32 secret;
    if (!BuildPrologue(context_, key_id_, prologue) || !CopySecret(*key, secret)) {
        return Fail();
    }

    try {
        handshake_.reset(new noise::NoisePskHandshake(
            noise::HandshakeRole::NetworkClientInitiator, std::move(secret), prologue));
    }
    catch (...) {
        return Fail();
    }
    if (!handshake_ || !handshake_->IsValid()) return Fail();

    std::vector<std::uint8_t> message;
    if (!handshake_->WriteMessage1(message) ||
        !HexEncode(message.data(), message.size(), output.message)) {
        return Fail();
    }
    output.action = TransportAuthAction::Advertise;
    output.methods.emplace_back(TransportAuthNoisePskV1Method);
    output.method = TransportAuthNoisePskV1Method;
    output.key_id.assign(key_id_.data(), key_id_.size());
    output.token.assign(context_.token.data(), context_.token.size());
    output.sequence = 1;
    state_ = State::AwaitingSelection;
    return true;
}

bool TransportAuthInitiator::ConsumeSelection(
    const TransportAuthControl& selection,
    TransportAuthControl& proof) noexcept {
    proof = TransportAuthControl{};
    if (state_ != State::AwaitingSelection || !handshake_ ||
        !IsExactSelection(selection, key_id_, context_.token)) {
        return Fail();
    }

    std::array<std::uint8_t, noise::NoiseHandshakeMessageSize> message{};
    const bool decoded = HexDecode(selection.message, message);
    const bool read = decoded && handshake_->ReadMessage2(message.data(), message.size());
    OPENSSL_cleanse(message.data(), message.size());
    if (!read || !handshake_->TakeResult(result_)) return Fail();

    noise::ClientSuccessProof confirmation{};
    if (!result_.GenerateClientSuccessConfirmationProof(confirmation) ||
        !HexEncode(confirmation.data(), confirmation.size(), proof.proof)) {
        OPENSSL_cleanse(confirmation.data(), confirmation.size());
        return Fail();
    }
    OPENSSL_cleanse(confirmation.data(), confirmation.size());
    proof.action = TransportAuthAction::Success;
    proof.method = TransportAuthNoisePskV1Method;
    proof.key_id.assign(key_id_.data(), key_id_.size());
    proof.token.assign(context_.token.data(), context_.token.size());
    handshake_.reset();
    state_ = State::AwaitingAcknowledgement;
    return true;
}

bool TransportAuthInitiator::ConsumeAcknowledgement(
    const TransportAuthControl& acknowledgement) noexcept {
    if (state_ != State::AwaitingAcknowledgement ||
        !IsExactSuccess(acknowledgement, key_id_, context_.token, false)) {
        return Fail();
    }
    state_ = State::Complete;
    return true;
}

bool TransportAuthInitiator::TakeNoiseResult(
    noise::NoisePskHandshakeResult& output) noexcept {
    if (state_ != State::Complete || output.IsValid() || !result_.IsValid()) return false;
    output = std::move(result_);
    state_ = State::ResultTaken;
    return true;
}

void TransportAuthInitiator::Abort() noexcept {
    Fail();
}

bool TransportAuthInitiator::Fail() noexcept {
    handshake_.reset();
    result_.Clear();
    state_ = State::Failed;
    return false;
}

TransportAuthResponder::TransportAuthResponder(
    std::shared_ptr<const configurations::TransportAuthKeyringSnapshot> keyring,
    const TransportAuthNegotiationContext& context)
    : keyring_(std::move(keyring)), context_(context) {
    if (!keyring_ || !IsSupportedCarrierContext(context_) ||
        (!context_.token.empty() && !IsCanonicalToken(context_.token))) {
        return;
    }
    state_ = State::AwaitingAdvertisement;
}

bool TransportAuthResponder::ConsumeAdvertisement(
    const TransportAuthControl& advertisement,
    TransportAuthControl& output) noexcept {
    output = TransportAuthControl{};
    if (state_ != State::AwaitingAdvertisement || !keyring_ ||
        !IsExactAdvertisement(advertisement)) {
        return Fail(&output, nullptr);
    }

    const std::string advertised_token(advertisement.token.data(), advertisement.token.size());
    if (!context_.token.empty() && context_.token != advertised_token) {
        return Fail(&output, &advertised_token);
    }
    context_.token = advertised_token;

    const std::string advertised_key_id(
        advertisement.key_id.data(), advertisement.key_id.size());
    const configurations::TransportAuthKeyringSnapshot::Key* key =
        keyring_->FindVerifyKey(advertised_key_id);
    if (key == nullptr ||
        (key->state != configurations::TransportAuthKeyState::Active &&
         key->state != configurations::TransportAuthKeyState::VerifyOnly)) {
        return Fail(&output, &context_.token);
    }
    key_id_ = key->id;

    std::vector<std::uint8_t> prologue;
    noise::Secret32 secret;
    if (!BuildPrologue(context_, key_id_, prologue) || !CopySecret(*key, secret)) {
        return Fail(&output, &context_.token);
    }
    try {
        handshake_.reset(new noise::NoisePskHandshake(
            noise::HandshakeRole::NetworkServerResponder, std::move(secret), prologue));
    }
    catch (...) {
        return Fail(&output, &context_.token);
    }

    std::array<std::uint8_t, noise::NoiseHandshakeMessageSize> message1{};
    const bool decoded = HexDecode(advertisement.message, message1);
    const bool read = decoded && handshake_ && handshake_->IsValid() &&
        handshake_->ReadMessage1(message1.data(), message1.size());
    OPENSSL_cleanse(message1.data(), message1.size());
    if (!read) return Fail(&output, &context_.token);

    std::vector<std::uint8_t> message2;
    if (!handshake_->WriteMessage2(message2) ||
        !handshake_->TakeResult(result_) ||
        !HexEncode(message2.data(), message2.size(), output.message)) {
        return Fail(&output, &context_.token);
    }
    output.action = TransportAuthAction::Select;
    output.method = TransportAuthNoisePskV1Method;
    output.key_id.assign(key_id_.data(), key_id_.size());
    output.token.assign(context_.token.data(), context_.token.size());
    output.sequence = 2;
    handshake_.reset();
    state_ = State::AwaitingClientProof;
    return true;
}

bool TransportAuthResponder::ConsumeClientProof(
    const TransportAuthControl& proof,
    TransportAuthControl& output) noexcept {
    output = TransportAuthControl{};
    if (state_ != State::AwaitingClientProof || !result_.IsValid() ||
        !IsExactSuccess(proof, key_id_, context_.token, true)) {
        return Fail(&output, &context_.token);
    }

    noise::ClientSuccessProof decoded_proof{};
    const bool decoded = HexDecode(proof.proof, decoded_proof);
    const bool verified = decoded &&
        result_.VerifyClientSuccessConfirmationProof(decoded_proof);
    OPENSSL_cleanse(decoded_proof.data(), decoded_proof.size());
    if (!verified) return Fail(&output, &context_.token);

    output.action = TransportAuthAction::Success;
    output.method = TransportAuthNoisePskV1Method;
    output.key_id.assign(key_id_.data(), key_id_.size());
    output.token.assign(context_.token.data(), context_.token.size());
    state_ = State::Complete;
    return true;
}

bool TransportAuthResponder::TakeNoiseResult(
    noise::NoisePskHandshakeResult& output) noexcept {
    if (state_ != State::Complete || output.IsValid() || !result_.IsValid()) return false;
    output = std::move(result_);
    state_ = State::ResultTaken;
    return true;
}

void TransportAuthResponder::Abort() noexcept {
    Fail(nullptr, nullptr);
}

bool TransportAuthResponder::Fail(
    TransportAuthControl* reject,
    const std::string* token) noexcept {
    handshake_.reset();
    result_.Clear();
    state_ = State::Failed;
    if (reject != nullptr) MakeReject(*reject, token);
    return false;
}

}
