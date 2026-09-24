#include <ios/IosP2PDatagramTransport.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <vector>

namespace ppp {
    namespace p2p {
        namespace {

            struct IosProviderReceiveState
                : public std::enable_shared_from_this<IosProviderReceiveState> {
                explicit IosProviderReceiveState(
                        boost::asio::io_context& context) noexcept
                    : io_context(context) {}

                boost::asio::io_context& io_context;
                std::mutex mutex;
                P2PDatagramReceiveCallback callback;
                std::atomic<bool> closed{false};
            };

            bool DecodeEndpoint(
                    const uint8_t* address,
                    int address_size,
                    uint16_t port,
                    boost::asio::ip::udp::endpoint& endpoint) noexcept {
                if (!address) {
                    return false;
                }
                if (address_size == 4) {
                    boost::asio::ip::address_v4::bytes_type bytes{};
                    std::memcpy(bytes.data(), address, bytes.size());
                    endpoint = {boost::asio::ip::address_v4(bytes), port};
                    return true;
                }
                if (address_size == 16) {
                    boost::asio::ip::address_v6::bytes_type bytes{};
                    std::memcpy(bytes.data(), address, bytes.size());
                    endpoint = {boost::asio::ip::address_v6(bytes), port};
                    return true;
                }
                return false;
            }

            void ProviderReceive(
                    void* receive_context,
                    int status,
                    const uint8_t* source_address,
                    int source_address_size,
                    uint16_t source_port,
                    const void* packet,
                    int packet_size) {
                auto* state = static_cast<IosProviderReceiveState*>(receive_context);
                if (!state || state->closed.load(std::memory_order_acquire)) {
                    return;
                }

                boost::asio::ip::udp::endpoint sender;
                const bool packet_valid = status == 0 && packet && packet_size > 0 &&
                    DecodeEndpoint(source_address, source_address_size,
                        source_port, sender);
                try {
                    std::vector<uint8_t> copy;
                    if (packet_valid) {
                        const auto* bytes = static_cast<const uint8_t*>(packet);
                        copy.assign(bytes, bytes + packet_size);
                    }
                    const auto receive_status = packet_valid
                        ? P2PDatagramReceiveStatus::Packet
                        : P2PDatagramReceiveStatus::Error;
                    auto shared_state = state->shared_from_this();
                    boost::asio::post(state->io_context,
                        [shared_state, receive_status, sender,
                         copy = std::move(copy)]() noexcept {
                        if (shared_state->closed.load(std::memory_order_acquire)) {
                            return;
                        }
                        P2PDatagramReceiveCallback callback;
                        {
                            std::lock_guard<std::mutex> lock(shared_state->mutex);
                            callback = shared_state->callback;
                        }
                        if (callback) {
                            callback(receive_status, sender,
                                copy.empty() ? nullptr : copy.data(),
                                static_cast<int>(copy.size()));
                        }
                    });
                }
                catch (...) {
                    return;
                }
            }

            class IosProviderP2PDatagramTransport final
                : public IP2PDatagramTransport {
            public:
                IosProviderP2PDatagramTransport(
                        boost::asio::io_context& io_context,
                        const openppp2_ios_p2p_datagram_provider& provider,
                        void* user_data) noexcept
                    : provider_(provider),
                      user_data_(user_data),
                      receive_state_(
                          std::make_shared<IosProviderReceiveState>(io_context)) {}

                ~IosProviderP2PDatagramTransport() noexcept override {
                    Close();
                }

                bool IsReady() const noexcept override {
                    return !receive_state_->closed.load(std::memory_order_acquire) &&
                        provider_.ready(user_data_) != 0;
                }

                bool Start(const P2PDatagramReceiveCallback& callback) noexcept override {
                    if (!callback || !IsReady()) {
                        return false;
                    }
                    {
                        std::lock_guard<std::mutex> lock(receive_state_->mutex);
                        receive_state_->callback = callback;
                    }
                    // Create the handle under the lock, but invoke
                    // provider_.start without holding it: the provider may
                    // deliver callbacks that re-enter this transport.
                    void* handle = nullptr;
                    {
                        std::lock_guard<std::mutex> lock(handle_mutex_);
                        if (!receive_state_->closed.load(std::memory_order_acquire) &&
                            !handle_) {
                            handle_ = provider_.create(
                                ProviderReceive, receive_state_.get(), user_data_);
                            handle = handle_;
                        }
                    }
                    const bool started = handle && provider_.start(handle) != 0;
                    if (!started) {
                        Close();
                        return false;
                    }
                    return true;
                }

                boost::asio::ip::udp::endpoint LocalEndpoint() const noexcept override {
                    return {};
                }

                bool SendTo(
                        const uint8_t* packet,
                        int packet_size,
                        const boost::asio::ip::udp::endpoint& endpoint) noexcept override {
                    if (receive_state_->closed.load(std::memory_order_acquire) ||
                        !packet || packet_size < 1 || endpoint.address().is_unspecified()) {
                        return false;
                    }

                    std::array<uint8_t, 16> address{};
                    int address_size = 0;
                    if (endpoint.address().is_v4()) {
                        const auto bytes = endpoint.address().to_v4().to_bytes();
                        address_size = static_cast<int>(bytes.size());
                        std::memcpy(address.data(), bytes.data(), bytes.size());
                    } else {
                        const auto bytes = endpoint.address().to_v6().to_bytes();
                        address_size = static_cast<int>(bytes.size());
                        std::memcpy(address.data(), bytes.data(), bytes.size());
                    }
                    // Register the in-flight send under the lock, then invoke
                    // the provider without holding it (the provider may
                    // synchronously re-enter this transport).  Close() drains
                    // sends_in_flight_ before closing the handle, so the raw
                    // pointer stays valid for the whole call.
                    void* handle = nullptr;
                    {
                        std::lock_guard<std::mutex> lock(handle_mutex_);
                        if (receive_state_->closed.load(std::memory_order_acquire) ||
                            !handle_) {
                            return false;
                        }
                        handle = handle_;
                        ++sends_in_flight_;
                    }
                    const int sent = provider_.send(handle, address.data(),
                        address_size, endpoint.port(), packet, packet_size);
                    {
                        std::lock_guard<std::mutex> lock(handle_mutex_);
                        if (--sends_in_flight_ == 0) {
                            sends_drained_.notify_all();
                        }
                    }
                    return sent != 0;
                }

                void Close() noexcept override {
                    if (receive_state_->closed.exchange(true,
                            std::memory_order_acq_rel)) {
                        return;
                    }
                    void* handle = nullptr;
                    {
                        std::unique_lock<std::mutex> lock(handle_mutex_);
                        handle = handle_;
                        handle_ = nullptr;
                        // Close must not run while a provider send is still
                        // executing (use-after-close); wait for the drain.
                        sends_drained_.wait(lock,
                            [this]() noexcept { return sends_in_flight_ == 0; });
                    }
                    if (handle) {
                        provider_.close(handle);
                    }
                    std::lock_guard<std::mutex> lock(receive_state_->mutex);
                    receive_state_->callback = nullptr;
                }

            private:
                openppp2_ios_p2p_datagram_provider provider_;
                void* user_data_ = nullptr;
                void* handle_ = nullptr;
                int sends_in_flight_ = 0;
                std::mutex handle_mutex_;
                std::condition_variable sends_drained_;
                std::shared_ptr<IosProviderReceiveState> receive_state_;
            };

            class IosProviderP2PDatagramTransportFactory final
                : public IP2PDatagramTransportFactory {
            public:
                IosProviderP2PDatagramTransportFactory(
                        const openppp2_ios_p2p_datagram_provider& provider,
                        void* user_data) noexcept
                    : provider_(provider), user_data_(user_data) {}

                std::shared_ptr<IP2PDatagramTransport> Create(
                        boost::asio::io_context& io_context) noexcept override {
                    return std::make_shared<IosProviderP2PDatagramTransport>(
                        io_context, provider_, user_data_);
                }

            private:
                openppp2_ios_p2p_datagram_provider provider_;
                void* user_data_ = nullptr;
            };

        }

        std::shared_ptr<IP2PDatagramTransportFactory>
        CreateIosProviderP2PDatagramTransportFactory(
                const openppp2_ios_p2p_datagram_provider& provider,
                void* user_data) noexcept {
            if (!provider.ready || !provider.create || !provider.start ||
                !provider.send || !provider.close || !user_data) {
                return nullptr;
            }
            return std::make_shared<IosProviderP2PDatagramTransportFactory>(
                provider, user_data);
        }

    }
}
