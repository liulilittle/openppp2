#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ppp {
    namespace configurations {
        enum class TransportAuthKeyState {
            Active,
            VerifyOnly,
            Revoked,
        };

        struct TransportAuthKeyMetadata final {
            std::string                     id;
            TransportAuthKeyState           state = TransportAuthKeyState::Revoked;
            std::string                     secret_file;
        };

        struct TransportAuthConfiguration final {
            static constexpr int            DefaultHandshakeTimeoutMs = 5000;
            static constexpr int            MinHandshakeTimeoutMs = 1000;
            static constexpr int            MaxHandshakeTimeoutMs = 30000;
            static constexpr std::size_t    MaxKeys = 8;
            static constexpr std::size_t    MaxVerifyOnlyKeys = 2;

            int                             handshake_timeout_ms = DefaultHandshakeTimeoutMs;
            std::vector<TransportAuthKeyMetadata> keys;

            void Clear() noexcept;
            bool Normalize(bool enabled, std::string* error = nullptr) noexcept;
        };

        const char* TransportAuthKeyStateToString(TransportAuthKeyState state) noexcept;
        bool TryParseTransportAuthKeyState(const std::string& value, TransportAuthKeyState& state) noexcept;

        class TransportAuthSecret final {
        public:
            static constexpr std::size_t Size = 32;

            TransportAuthSecret() noexcept;
            ~TransportAuthSecret() noexcept;
            TransportAuthSecret(const TransportAuthSecret&) = delete;
            TransportAuthSecret& operator=(const TransportAuthSecret&) = delete;
            TransportAuthSecret(TransportAuthSecret&& other) noexcept;
            TransportAuthSecret& operator=(TransportAuthSecret&& other) noexcept;

            const unsigned char* data() const noexcept { return bytes_.data(); }
            std::size_t size() const noexcept { return bytes_.size(); }

        private:
            friend bool LoadTransportAuthSecretFile(const std::string&, TransportAuthSecret&, std::string*) noexcept;
            std::array<unsigned char, Size> bytes_{};
        };

        bool LoadTransportAuthSecretFile(
            const std::string& path,
            TransportAuthSecret& secret,
            std::string* error = nullptr) noexcept;

        class TransportAuthKeyringSnapshot final {
        public:
            struct Key final {
                std::string                 id;
                TransportAuthKeyState       state = TransportAuthKeyState::Revoked;
                TransportAuthSecret         secret;

                Key() noexcept = default;
                Key(Key&&) noexcept = default;
                Key& operator=(Key&&) noexcept = default;
                Key(const Key&) = delete;
                Key& operator=(const Key&) = delete;
            };

            TransportAuthKeyringSnapshot(const TransportAuthKeyringSnapshot&) = delete;
            TransportAuthKeyringSnapshot& operator=(const TransportAuthKeyringSnapshot&) = delete;

            std::uint64_t generation() const noexcept { return generation_; }
            const Key* active() const noexcept;
            const Key* FindEmitKey(const std::string& id) const noexcept;
            const Key* FindVerifyKey(const std::string& id) const noexcept;
            std::size_t verify_key_count() const noexcept { return verify_keys_.size(); }

            static std::shared_ptr<const TransportAuthKeyringSnapshot> Build(
                const TransportAuthConfiguration& configuration,
                std::string* error = nullptr) noexcept;

        private:
            TransportAuthKeyringSnapshot() noexcept;

            std::uint64_t                   generation_;
            std::unique_ptr<Key>            active_key_;
            std::vector<Key>                verify_keys_;
        };

        inline std::shared_ptr<const TransportAuthKeyringSnapshot> BuildTransportAuthKeyringSnapshot(
            const TransportAuthConfiguration& configuration,
            std::string* error = nullptr) noexcept {
            return TransportAuthKeyringSnapshot::Build(configuration, error);
        }
    }
}
