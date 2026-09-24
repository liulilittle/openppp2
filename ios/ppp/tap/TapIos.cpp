#include <ios/ppp/tap/TapIos.h>
#include <ppp/p2p/P2PDatagramTransport.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Executors.h>

namespace ppp
{
    namespace tap
    {
        namespace
        {
            struct TapIosPacketOwner
            {
                std::shared_ptr<Byte> packet;
            };

            void ReleaseTapIosPacket(void* context) noexcept
            {
                delete static_cast<TapIosPacketOwner*>(context);
            }
        }

        TapIos::TapIos(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string&                              dev,
            uint32_t                                        address,
            uint32_t                                        gw,
            uint32_t                                        mask,
            bool                                            hosted_network) noexcept
            : ITap(context, dev, INVALID_HANDLE_VALUE, address, gw, mask, hosted_network)
            , opened_(false)
            , output_(NULLPTR)
        {
        }

        std::shared_ptr<TapIos> TapIos::Create(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string&                              dev,
            uint32_t                                        ip,
            uint32_t                                        gw,
            uint32_t                                        mask,
            bool                                            promisc,
            bool                                            hosted_network,
            const ppp::vector<uint32_t>&                    dns_addresses) noexcept
        {
            (void)promisc;
            (void)dns_addresses;

            ppp::string device_id = dev.empty() ? ppp::string("packet-tunnel") : dev;
            std::shared_ptr<TapIos> tap = ppp::make_shared_object<TapIos>(context, device_id, ip, gw, mask, hosted_network);
            if (NULLPTR == tap)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            return tap;
        }

        void TapIos::SetPacketOutput(PacketOutputEventHandler output) noexcept
        {
            std::lock_guard<std::mutex> scope(output_mutex_);
            output_ = output;
        }

        bool TapIos::Input(const void* packet, int packet_size) noexcept
        {
            if (NULLPTR == packet || packet_size < 1)
            {
                return false;
            }

            if (!IsOpen() || NULLPTR == GetPacketInput())
            {
                return false;
            }

            PacketInputEventArgs e;
            e.Packet = const_cast<void*>(packet);
            e.PacketLength = packet_size;
            OnInput(e);
            return true;
        }

        void TapIos::SetP2PDatagramTransportFactory(
            const std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory>& factory) noexcept
        {
            std::lock_guard<std::mutex> scope(p2p_factory_mutex_);
            p2p_factory_ = factory;
        }

        std::shared_ptr<ppp::p2p::IP2PDatagramTransportFactory>
            TapIos::GetP2PDatagramTransportFactory() const noexcept
        {
            std::lock_guard<std::mutex> scope(p2p_factory_mutex_);
            return p2p_factory_;
        }

        bool TapIos::IsReady() noexcept
        {
            return NULLPTR != GetContext();
        }

        bool TapIos::IsOpen() noexcept
        {
            return opened_.load() && IsReady();
        }

        bool TapIos::Open() noexcept
        {
            opened_.store(IsReady());
            return opened_.load();
        }

        void TapIos::Dispose() noexcept
        {
            opened_.store(false);
            {
                std::lock_guard<std::mutex> scope(output_mutex_);
                output_ = NULLPTR;
            }
            ITap::Dispose();
        }

        bool TapIos::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept
        {
            if (!IsOpen() || NULLPTR == packet || packet_size < 1)
            {
                return false;
            }

            PacketOutputEventHandler output;
            {
                std::lock_guard<std::mutex> scope(output_mutex_);
                output = output_;
            }

            if (NULLPTR == output)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                return false;
            }

            TapIosPacketOwner* owner = new (std::nothrow) TapIosPacketOwner();
            if (NULLPTR == owner)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            owner->packet = packet;
            bool ok = output(packet.get(), packet_size, owner, ReleaseTapIosPacket);
            if (!ok)
            {
                ReleaseTapIosPacket(owner);
            }
            return ok;
        }

        bool TapIos::Output(const void* packet, int packet_size) noexcept
        {
            if (!IsOpen() || NULLPTR == packet || packet_size < 1)
            {
                return false;
            }

            std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(BufferAllocator, packet_size);
            if (NULLPTR == buffer)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            memcpy(buffer.get(), packet, packet_size);
            return Output(buffer, packet_size);
        }

        bool TapIos::SetInterfaceMtu(int mtu) noexcept
        {
            return mtu > 0 && mtu <= ITap::Mtu;
        }
    }
}
