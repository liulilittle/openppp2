#pragma once

#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/configurations/TransportAuthConfiguration.h>
#include <ppp/cryptography/noise/NoisePsk.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace ppp::app::protocol {

inline constexpr char TransportAuthNoisePskV1Method[] = "noise-psk-v1";
inline constexpr std::size_t TransportAuthTokenHexLength = TransportAuthControl::TokenHexLength;

enum class TransportAuthCarrier : std::uint8_t {
    Tcp = 1,
    WebSocket = 2,
    TlsWebSocket = 3,
};

struct TransportAuthNegotiationContext final {
    TransportAuthCarrier carrier = TransportAuthCarrier::Tcp;
    ppp::cryptography::noise::SessionId session_id{};
    /** Initiators require a canonical token; responders may leave it empty for adoption. */
    std::string token;
};

class TransportAuthInitiator final {
public:
    enum class State : std::uint8_t {
        Invalid,
        Ready,
        AwaitingSelection,
        AwaitingAcknowledgement,
        Complete,
        Failed,
        ResultTaken,
    };

    TransportAuthInitiator(
        std::shared_ptr<const ppp::configurations::TransportAuthKeyringSnapshot> keyring,
        const TransportAuthNegotiationContext& context);

    TransportAuthInitiator(const TransportAuthInitiator&) = delete;
    TransportAuthInitiator& operator=(const TransportAuthInitiator&) = delete;

    State GetState() const noexcept { return state_; }
    bool IsFailed() const noexcept { return state_ == State::Failed || state_ == State::Invalid; }
    bool CanTakeNoiseResult() const noexcept { return state_ == State::Complete; }

    bool CreateAdvertisement(TransportAuthControl& output) noexcept;
    bool ConsumeSelection(
        const TransportAuthControl& selection,
        TransportAuthControl& proof) noexcept;
    bool ConsumeAcknowledgement(const TransportAuthControl& acknowledgement) noexcept;
    bool TakeNoiseResult(
        ppp::cryptography::noise::NoisePskHandshakeResult& output) noexcept;
    void Abort() noexcept;

private:
    bool Fail() noexcept;

    State state_ = State::Invalid;
    std::shared_ptr<const ppp::configurations::TransportAuthKeyringSnapshot> keyring_;
    TransportAuthNegotiationContext context_;
    std::string key_id_;
    std::unique_ptr<ppp::cryptography::noise::NoisePskHandshake> handshake_;
    ppp::cryptography::noise::NoisePskHandshakeResult result_;
};

class TransportAuthResponder final {
public:
    enum class State : std::uint8_t {
        Invalid,
        AwaitingAdvertisement,
        AwaitingClientProof,
        Complete,
        Failed,
        ResultTaken,
    };

    /** An empty context token is adopted once from the first valid advertisement. */
    TransportAuthResponder(
        std::shared_ptr<const ppp::configurations::TransportAuthKeyringSnapshot> keyring,
        const TransportAuthNegotiationContext& context);

    TransportAuthResponder(const TransportAuthResponder&) = delete;
    TransportAuthResponder& operator=(const TransportAuthResponder&) = delete;

    State GetState() const noexcept { return state_; }
    bool IsFailed() const noexcept { return state_ == State::Failed || state_ == State::Invalid; }
    bool CanTakeNoiseResult() const noexcept { return state_ == State::Complete; }

    /** A reject echoes the token only after the advertisement token is validated. */
    bool ConsumeAdvertisement(
        const TransportAuthControl& advertisement,
        TransportAuthControl& output) noexcept;
    /** A reject echoes the token locked by the accepted advertisement. */
    bool ConsumeClientProof(
        const TransportAuthControl& proof,
        TransportAuthControl& output) noexcept;
    bool TakeNoiseResult(
        ppp::cryptography::noise::NoisePskHandshakeResult& output) noexcept;
    void Abort() noexcept;

private:
    bool Fail(TransportAuthControl* reject, const std::string* token) noexcept;

    State state_ = State::Invalid;
    std::shared_ptr<const ppp::configurations::TransportAuthKeyringSnapshot> keyring_;
    TransportAuthNegotiationContext context_;
    std::string key_id_;
    std::unique_ptr<ppp::cryptography::noise::NoisePskHandshake> handshake_;
    ppp::cryptography::noise::NoisePskHandshakeResult result_;
};

}
