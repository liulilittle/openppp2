#pragma once

/**
 * @file ITap.h
 * @brief Declares the cross-platform TAP/TUN interface abstraction.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/tap/TxGsoMetadata.h>

namespace ppp
{
    namespace tap
    {
        /**
         * @brief Base abstraction for TAP/TUN adapters.
         *
         * This interface wraps platform-specific virtual network device handles,
         * packet input notifications, asynchronous I/O context integration, and
         * factory creation helpers for Windows/macOS/Linux backends.
         */
        class ITap : public std::enable_shared_from_this<ITap>
        {
            friend class                                                    WritePacketToKernelNio;
            /**
             * @brief Internal packet holder used for queued packet data.
             */
            struct                                                          PacketContent
            {
                std::shared_ptr<Byte>                                       Packet       = NULLPTR;
                int                                                         PacketLength = 0;
            };

        public:
            /**
             * @brief Event arguments for inbound packet notifications.
             */
            struct                                                          PacketInputEventArgs
            {
                void*                                                       Packet       = NULLPTR;
                int                                                         PacketLength = 0;
                bool                                                        TcpV4Gso     = false;
            };
            /**
             * @brief Callback signature invoked when a packet is read from device.
             */
            typedef ppp::function<bool(ITap*, PacketInputEventArgs&)>       PacketInputEventHandler;
            /**
             * @brief Returns whether a packet can be delivered as one complete TCPv4 GSO frame.
             * @note Callers without explicit GSO-consumer capability must return false so the
             *       platform TAP backend performs its per-MSS fallback.
             */
            static constexpr bool                                           ShouldDeliverWholeTcpV4Gso(const PacketInputEventArgs& event, bool consumer_capable) noexcept
            {
                return !event.TcpV4Gso || consumer_capable;
            }

        public:
            /**
             * @brief Local IPv4 address assigned to the virtual network interface.
             *
             * @note Initialised at construction from the static configuration but no
             *       longer `const`: when the server pushes a dynamic IPv4 assignment
             *       (see VEthernetNetworkSwitcher::ApplyAssignedIPv4) the field is
             *       updated to match the address actually programmed onto the kernel
             *       interface, so external consumers (e.g. UI status panels reading
             *       this member) see the live value rather than the stale config IP.
             *       RestoreAssignedIPv4 reverts the field to the original value.
             */
            uint32_t                                                        IPAddress      = ppp::net::IPEndPoint::AnyAddress;
            /** @brief IPv4 address of the default gateway routed via this adapter. See note on IPAddress. */
            uint32_t                                                        GatewayServer  = ppp::net::IPEndPoint::AnyAddress;
            /** @brief Subnet mask applied to the local interface address. See note on IPAddress. */
            uint32_t                                                        SubmaskAddress = ppp::net::IPEndPoint::AnyAddress;

        public:
            /** @brief Thread-safe setter for the inbound packet event handler (invoked for every packet received from the device). */
            void                                                            SetPacketInput(const PacketInputEventHandler& handler) noexcept;
            /** @brief Thread-safe snapshot of the inbound packet event handler. */
            PacketInputEventHandler                                         GetPacketInput() noexcept;
            /** @brief Shared swap-based memory allocator for packet buffer lifetimes. */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            BufferAllocator;

        public:
            /** @brief Maximum transmission unit in bytes, equal to the IP header MTU constant. */
            static constexpr int                                            Mtu = ppp::net::native::ip_hdr::MTU;

        public:
            /**
             * @brief Constructs a TAP object around an existing native handle.
             * @param context Asio context used for asynchronous operations.
             * @param id Device identifier.
             * @param tun Native TAP/TUN handle or backend object pointer.
             * @param ip Local interface IPv4 address.
             * @param gw Gateway IPv4 address.
             * @param mask Subnet mask.
             * @param hosted_network Indicates whether hosted-network mode is enabled.
             */
            ITap(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network);
            /**
             * @brief Releases TAP resources.
             */
            virtual ~ITap() noexcept;

        public:
            /**
             * @brief Checks whether the object has valid runtime resources.
             * @return true if context, handle, and stream/backend state are ready.
             */
            virtual bool                                                    IsReady() noexcept;
            /**
             * @brief Checks whether the TAP adapter is currently opened.
             * @return true when open flag is set and resources are ready.
             */
            virtual bool                                                    IsOpen() noexcept;
            /**
             * @brief Sets interface MTU on the platform backend.
             * @param mtu Target maximum transmission unit.
             * @return true if MTU update succeeds.
             */
            virtual bool                                                    SetInterfaceMtu(int mtu) noexcept = 0;
            /** @brief Whether this concrete device can accept validated TCPv4 GSO output. */
            virtual bool                                                    SupportsTxGso() const noexcept { return false; }
            /**
             * @brief Sends one validated L3 super-packet with explicit segmentation metadata.
             * @note The default is fail-closed; it must never route an oversized packet through Output().
             */
            virtual bool                                                    OutputGso(const std::shared_ptr<Byte>&, int, TxGsoMetadata) noexcept { return false; }

        public:
            /**
             * @brief Starts packet read loop.
             * @return true if asynchronous reading is started successfully.
             */
            virtual bool                                                    Open() noexcept;
            /**
             * @brief Schedules resource cleanup on the I/O context.
             */
            virtual void                                                    Dispose() noexcept;
            /**
             * @brief Sends a packet using shared buffer storage.
             * @param packet Packet payload buffer.
             * @param packet_size Packet payload length in bytes.
             * @return true if write dispatch is accepted.
             */
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept;
            /**
             * @brief Sends a packet from raw memory.
             * @param packet Packet payload pointer.
             * @param packet_size Packet payload length in bytes.
             * @return true if packet is queued for asynchronous write.
             */
            virtual bool                                                    Output(const void* packet, int packet_size) noexcept;

        public:
            /** @brief Returns the device identifier string. */
            const ppp::string&                                              GetId() noexcept             { return _id; }
            /** @brief Returns the io_context used by this adapter. */
            std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept        { return _context; }
            /** @brief Returns the native device handle or backend pointer. */
            void*                                                           GetHandle() noexcept         { return _handle; }
            /** @brief Returns a mutable reference to the OS network interface index. */
            int&                                                            GetInterfaceIndex() noexcept { return _interface_index; }
            /** @brief Returns whether hosted-network (bridged) mode is active. */
            bool                                                            IsHostedNetwork() noexcept   { return _hosted_network; }

        public:
            /**
             * @brief Finds an available device identifier for current platform.
             * @return Platform-specific TAP component/device hint string.
             */
            static ppp::string                                              FindAnyDevice() noexcept;

        public:
#if defined(_WIN32)
            /**
             * @brief Creates a TAP backend from numeric IPv4 parameters (Windows).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;
            /**
             * @brief Creates a TAP backend from textual IPv4 parameters (Windows).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept;
#else
            /**
             * @brief Creates a TAP backend from numeric IPv4 parameters (POSIX).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;
            /**
             * @brief Creates a TAP backend from textual IPv4 parameters (POSIX).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, bool promisc, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept;
#endif

        protected:
            /**
             * @brief Returns underlying asynchronous stream descriptor.
             */
            std::shared_ptr<boost::asio::posix::stream_descriptor>          GetStream() noexcept;
            /**
             * @brief Returns reusable packet buffer used for read operations.
             */
            Byte*                                                           GetPacketBuffers() noexcept { return _packet; }
            /**
             * @brief Raises inbound packet callback.
             * @param e Packet event arguments.
             */
            virtual void                                                    OnInput(PacketInputEventArgs& e) noexcept;
            /**
             * @brief Arms the next asynchronous read for packet input.
             * @return true if async read registration succeeds.
             */
            virtual bool                                                    AsynchronousReadPacketLoops() noexcept;

        private:
            /**
             * @brief Closes stream and clears packet callback.
             */
            void                                                            Finalize() noexcept;
            /**
             * @brief Drains the outbound write queue one async_write at a time.
             * @note  Always runs on _strand; re-entered from each write completion.
             */
            void                                                            DrainWriteQueue() noexcept;

        private:
            /** @brief Platform device identifier string (e.g., GUID on Windows, "tun0" on Linux). */
            ppp::string                                                     _id;
            struct {
                /** @brief Set while the adapter read loop is active. */
                bool                                                        _opening         : 1;
                /** @brief Set when hosted-network (bridged) mode is requested. */
                bool                                                        _hosted_network  : 7;
            };

            /** @brief Opaque native device handle or driver object pointer. */
            void*                                                           _handle          = NULLPTR;
            /** @brief OS-assigned network interface index (e.g., from if_nametoindex). */
            int                                                             _interface_index = -1;
            /** @brief Asio POSIX stream descriptor wrapping the TAP/TUN file descriptor. */
            std::shared_ptr<boost::asio::posix::stream_descriptor>          _stream;
            /** @brief Shared io_context used for all asynchronous read/write operations. */
            std::shared_ptr<boost::asio::io_context>                        _context;
            /** @brief Strand serialising read re-arm, write drain and Finalize on this adapter. */
            std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>> _strand;
            /** @brief Guards _stream publication (constructor/Finalize vs I/O paths). */
            std::mutex                                                      _stream_mutex;
            /** @brief Guards packet_input_ assignment/clear/copy. */
            std::mutex                                                      packet_input_mutex_;
            /** @brief Inbound packet event handler (was a public field; access via Set/GetPacketInput). */
            PacketInputEventHandler                                         packet_input_;
            /** @brief Guards _write_queue/_write_in_progress. */
            std::mutex                                                      _write_mutex;
            /** @brief Outbound packets waiting for the stream to become writable (one async_write at a time). */
            std::deque<std::pair<std::shared_ptr<Byte>, int>>               _write_queue;
            /** @brief True while an async_write is outstanding on _stream. */
            bool                                                            _write_in_progress = false;
            /** @brief Reusable buffer for ordinary MTU-sized packet reads.
             * Linux VNET/GSO reads are owned by TapLinux with its negotiated
             * per-instance virtio-header capacity.
             */
            Byte                                                            _packet[ITap::Mtu];
        };
    }
}
