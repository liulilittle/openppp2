#include <ppp/configurations/TransportAuthConfiguration.h>

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
    static void SetError(std::string* error, const char* message) noexcept {
        if (error != nullptr) {
            *error = message;
        }
    }

    static void Trim(std::string& value) noexcept {
        const std::size_t first = value.find_first_not_of(" \t\r\n\f\v");
        if (first == std::string::npos) {
            value.clear();
            return;
        }
        const std::size_t last = value.find_last_not_of(" \t\r\n\f\v");
        value = value.substr(first, last - first + 1);
    }

    static bool IsCanonicalHex(const unsigned char* value, std::size_t length) noexcept {
        if (length != ppp::configurations::TransportAuthSecret::Size * 2) {
            return false;
        }
        for (std::size_t i = 0; i < length; ++i) {
            const unsigned char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    static unsigned char DecodeNibble(unsigned char value) noexcept {
        return value <= '9' ? static_cast<unsigned char>(value - '0')
                            : static_cast<unsigned char>(value - 'a' + 10);
    }

    static bool IsCanonicalKeyId(const std::string& value) noexcept {
        if (value.empty() || value.size() > 63 ||
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

    static std::atomic<std::uint64_t> TransportAuthKeyringGeneration{0};

    static bool AllocateTransportAuthKeyringGeneration(
        std::uint64_t& generation, std::string* error) noexcept {
        std::uint64_t observed =
            TransportAuthKeyringGeneration.load(std::memory_order_relaxed);
        for (;;) {
            if (observed == std::numeric_limits<std::uint64_t>::max()) {
                SetError(error, "transport-auth keyring generation exhausted");
                return false;
            }
            const std::uint64_t next = observed + 1;
            if (TransportAuthKeyringGeneration.compare_exchange_weak(
                    observed, next, std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                generation = next;
                return true;
            }
        }
    }
}

namespace ppp {
    namespace configurations {
        void TransportAuthConfiguration::Clear() noexcept {
            handshake_timeout_ms = DefaultHandshakeTimeoutMs;
            keys.clear();
        }

        bool TransportAuthConfiguration::Normalize(bool enabled, std::string* error) noexcept {
            if (error != nullptr) {
                error->clear();
            }
            handshake_timeout_ms = std::max(MinHandshakeTimeoutMs,
                std::min(MaxHandshakeTimeoutMs, handshake_timeout_ms));

            if (keys.size() > MaxKeys) {
                SetError(error, "transport-auth key count exceeds 8");
                return false;
            }

            std::set<std::string> ids;
            std::size_t active_count = 0;
            std::size_t verify_only_count = 0;
            for (TransportAuthKeyMetadata& key : keys) {
                Trim(key.id);
                Trim(key.secret_file);
                if (!IsCanonicalKeyId(key.id)) {
                    SetError(error,
                        "transport-auth key ids must be 1..63 canonical lowercase characters");
                    return false;
                }
                if (!ids.emplace(key.id).second) {
                    SetError(error, "transport-auth key ids must be unique");
                    return false;
                }
                if (key.state == TransportAuthKeyState::Active) {
                    ++active_count;
                }
                else if (key.state == TransportAuthKeyState::VerifyOnly) {
                    ++verify_only_count;
                }
                else if (key.state != TransportAuthKeyState::Revoked) {
                    SetError(error, "transport-auth key state is invalid");
                    return false;
                }
                if (key.state != TransportAuthKeyState::Revoked && key.secret_file.empty()) {
                    SetError(error, "active and verify-only transport-auth keys require secret-file");
                    return false;
                }
            }

            if (verify_only_count > MaxVerifyOnlyKeys) {
                SetError(error, "transport-auth verify-only key count exceeds 2");
                return false;
            }
            if (active_count > 1 || (enabled && active_count != 1)) {
                SetError(error, "enabled transport-auth requires exactly one active key");
                return false;
            }
            return true;
        }

        const char* TransportAuthKeyStateToString(TransportAuthKeyState state) noexcept {
            switch (state) {
            case TransportAuthKeyState::Active:
                return "active";
            case TransportAuthKeyState::VerifyOnly:
                return "verify-only";
            default:
                return "revoked";
            }
        }

        bool TryParseTransportAuthKeyState(const std::string& value, TransportAuthKeyState& state) noexcept {
            if (value == "active") {
                state = TransportAuthKeyState::Active;
                return true;
            }
            if (value == "verify-only") {
                state = TransportAuthKeyState::VerifyOnly;
                return true;
            }
            if (value == "revoked") {
                state = TransportAuthKeyState::Revoked;
                return true;
            }
            return false;
        }

        TransportAuthSecret::TransportAuthSecret() noexcept = default;

        TransportAuthSecret::~TransportAuthSecret() noexcept {
            OPENSSL_cleanse(bytes_.data(), bytes_.size());
        }

        TransportAuthSecret::TransportAuthSecret(TransportAuthSecret&& other) noexcept {
            std::memcpy(bytes_.data(), other.bytes_.data(), bytes_.size());
            OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
        }

        TransportAuthSecret& TransportAuthSecret::operator=(TransportAuthSecret&& other) noexcept {
            if (this != &other) {
                OPENSSL_cleanse(bytes_.data(), bytes_.size());
                std::memcpy(bytes_.data(), other.bytes_.data(), bytes_.size());
                OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
            }
            return *this;
        }

        bool LoadTransportAuthSecretFile(
            const std::string& path,
            TransportAuthSecret& secret,
            std::string* error) noexcept {
            if (nullptr != error) {
                error->clear();
            }
            unsigned char encoded[TransportAuthSecret::Size * 2 + 1]{};
            std::size_t encoded_size = 0;
            bool loaded = false;

#if defined(_WIN32)
            (void)path;
            SetError(error,
                "transport-auth secret-file loading is unsupported on Windows");
#else
            int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0) {
                SetError(error, "cannot open transport-auth secret-file");
            }
            else {
                struct stat st{};
                if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
                    SetError(error, "transport-auth secret-file must be a regular file");
                }
                else if (st.st_uid != geteuid()) {
                    SetError(error, "transport-auth secret-file must be owned by current uid");
                }
                else if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
                    SetError(error, "transport-auth secret-file group/other permissions must be zero");
                }
                else if (st.st_size != static_cast<off_t>(TransportAuthSecret::Size * 2)) {
                    SetError(error, "transport-auth secret-file must contain exactly 64 bytes");
                }
                else {
                    while (encoded_size < sizeof(encoded)) {
                        const ssize_t count = read(fd, encoded + encoded_size, sizeof(encoded) - encoded_size);
                        if (count > 0) {
                            encoded_size += static_cast<std::size_t>(count);
                            continue;
                        }
                        if (count < 0 && errno == EINTR) {
                            continue;
                        }
                        loaded = count == 0 && encoded_size == TransportAuthSecret::Size * 2;
                        break;
                    }
                    if (!loaded) {
                        SetError(error, "cannot read complete transport-auth secret-file");
                    }
                }
                close(fd);
            }
#endif

            bool valid = loaded && IsCanonicalHex(encoded, encoded_size);
            if (loaded && !valid) {
                SetError(error, "transport-auth secret-file must be canonical lowercase hex");
            }
            if (valid) {
                for (std::size_t i = 0; i < secret.bytes_.size(); ++i) {
                    secret.bytes_[i] = static_cast<unsigned char>(
                        (DecodeNibble(encoded[i * 2]) << 4) | DecodeNibble(encoded[i * 2 + 1]));
                }
            }
            else {
                OPENSSL_cleanse(secret.bytes_.data(), secret.bytes_.size());
            }
            OPENSSL_cleanse(encoded, sizeof(encoded));
            return valid;
        }

        TransportAuthKeyringSnapshot::TransportAuthKeyringSnapshot() noexcept
            : generation_(0) {
        }

        const TransportAuthKeyringSnapshot::Key* TransportAuthKeyringSnapshot::active() const noexcept {
            return active_key_.get();
        }

        const TransportAuthKeyringSnapshot::Key* TransportAuthKeyringSnapshot::FindEmitKey(
            const std::string& id) const noexcept {
            const Key* key = active_key_.get();
            return nullptr != key && key->id == id ? key : nullptr;
        }

        const TransportAuthKeyringSnapshot::Key* TransportAuthKeyringSnapshot::FindVerifyKey(
            const std::string& id) const noexcept {
            const Key* key = FindEmitKey(id);
            if (nullptr != key) {
                return key;
            }
            for (const Key& candidate : verify_keys_) {
                if (candidate.id == id) {
                    return &candidate;
                }
            }
            return nullptr;
        }

        std::shared_ptr<const TransportAuthKeyringSnapshot> TransportAuthKeyringSnapshot::Build(
            const TransportAuthConfiguration& configuration,
            std::string* error) noexcept {
            try {
                TransportAuthConfiguration normalized = configuration;
                if (!normalized.Normalize(true, error)) {
                    return nullptr;
                }

                std::shared_ptr<TransportAuthKeyringSnapshot> snapshot(
                    new TransportAuthKeyringSnapshot());
                snapshot->verify_keys_.reserve(TransportAuthConfiguration::MaxVerifyOnlyKeys);
                for (const TransportAuthKeyMetadata& metadata : normalized.keys) {
                    if (metadata.state == TransportAuthKeyState::Revoked) {
                        continue;
                    }
                    Key key;
                    key.id = metadata.id;
                    key.state = metadata.state;
                    if (!LoadTransportAuthSecretFile(metadata.secret_file, key.secret, error)) {
                        return nullptr;
                    }
                    if (metadata.state == TransportAuthKeyState::Active) {
                        snapshot->active_key_.reset(new Key(std::move(key)));
                    }
                    else {
                        snapshot->verify_keys_.emplace_back(std::move(key));
                    }
                }
                if (!AllocateTransportAuthKeyringGeneration(
                        snapshot->generation_, error)) {
                    return nullptr;
                }
                return snapshot;
            }
            catch (...) {
                SetError(error, "cannot build transport-auth keyring snapshot");
                return nullptr;
            }
        }
    }
}
