                virtual bool CanConsumeTcpV4Gso() noexcept override;
                virtual bool OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept override;
                virtual bool OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept override;
                virtual bool OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;
                virtual bool OnTick(uint64_t now) noexcept override;
                virtual bool OnUpdate(uint64_t now) noexcept override;
                virtual bool OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;
                virtual bool OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information, const VirtualEthernetInformationExtensions& extensions) noexcept;
                bool ApplyPeerPrefixRoutes(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void ClearPeerPrefixRoutes() noexcept;

                virtual std::shared_ptr<VEthernetExchanger> NewExchanger() noexcept;
                virtual std::shared_ptr<ppp::ethernet::VNetstack> NewNetstack() noexcept override;
                virtual VEthernetHttpProxySwitcherPtr NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual VEthernetSocksProxySwitcherPtr NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS> NewQoS() noexcept;
                virtual ITransmissionStatisticsPtr NewStatistics() noexcept;

#if defined(_WIN32)
                virtual PaperAirplaneControllerPtr NewPaperAirplaneController() noexcept;
#elif defined(_LINUX)
                virtual ProtectorNetworkPtr NewProtectorNetwork() noexcept;
#endif

                virtual bool DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching = true) noexcept;
                virtual bool DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const std::shared_ptr<Byte>& owner, void* packet, int packet_size, bool caching = true) noexcept;
                boost::asio::ip::address RewriteFakeIpAddress(const boost::asio::ip::address& addr) const noexcept;
                bool ResolveDestination(
                    const ppp::net::IPEndPoint& endpoint,
                    routing::ResolvedDestination& destination) const noexcept;
