                bool                                                               manual_ipv4_ = false;
                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                const ppp::app::TcpStackMode                                        tcp_stack_mode_ = ppp::app::TcpStackMode::Native;
                ppp::string                                                         requested_ipv6_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>                 qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>          statistics_;
                VEthernetIcmpPacketTable                                            icmppackets_;
                std::unique_ptr<QuicRejectRateLimiter>                              quic_reject_limiter_;
                struct {
                    int                                                             icmppackets_aid_  = 0;
                    bool                                                            block_quic_       = false;
                    bool                                                            static_mode_      = false;
                    bool                                                            proxy_only_       = false;
                    // Proxy-only runtime joined to the virtual subnet: the in-process stack is the
                    // subnet member and host sockets must never carry subnet traffic.
                    bool                                                            proxy_subnet_userspace_ = false;
                    // Proxy-only runtime that also proxies Internet destinations (off: subnet only).
                    bool                                                            proxy_internet_ = true;
                    uint16_t                                                        mux_              = 0;
                    uint8_t                                                         mux_acceleration_ = 0;
                };
                // Proxy-only subnet: virtual-IP TCP port -> 127.0.0.1 port that peers may open.
                ppp::unordered_map<uint16_t, uint16_t>                              proxy_subnet_forwards_;
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                VEthernetSocksProxySwitcherPtr                                      socks_proxy_;
                std::unique_ptr<SwitcherTimeoutRegistry>                            timeout_registry_;
                std::shared_ptr<dns::DnsController>                                 dns_controller_;
                std::shared_ptr<const dns::DnsSessionContext>                       dns_session_;
                RouteIPListTablePtr                                                 vbgp_;
                ppp::string                                                         server_ru_;
                std::shared_ptr<aggligator::aggligator>                             aggligator_;
                IForwardingPtr                                                      forwarding_;
                std::unique_ptr<VirtualEthernetInformationExtensions>               information_extensions_;
                ppp::vector<ppp::app::protocol::PeerPrefixRouteEntry>               dynamic_peer_routes_;
                ppp::vector<net::native::RouteEntry>                                applied_peer_prefix_routes_;

#if !defined(_ANDROID) && !defined(_IPHONE)
                SynchronizedObject                                                  prdr_;
#if defined(_LINUX)
                bool                                                                protect_mode_  = false;
#endif
#endif

#if defined(_LINUX)
                ProtectorNetworkPtr                                                 protect_network_;
#endif

#if defined(_ANDROID) || defined(_IPHONE)
                ppp::string                                                         bypass_ip_list_;
#else
                LoadIPListFileVectorPtr                                             ribs_;
                std::shared_ptr<ClientNetworkInterface>                             tun_ni_;
                std::shared_ptr<ClientNetworkInterface>                             underlying_ni_;
                ppp::string                                                         preferred_nic_;
                boost::asio::ip::address                                            preferred_ngw_;

#if defined(_WIN32)
                PaperAirplaneControllerPtr                                          paper_airplane_ctrl_;
                // One explicitly authorized TAP adapter per session.  Values
                // remain until compare-and-restore succeeds.
                NetworkDnsSnapshots                                                ni_dns_snapshots_;
                std::unique_ptr<ppp::win32::ipv6::WindowsIPv6RouteOwner>            windows_ipv6_route_owner_;
#elif defined(_LINUX)
                ppp::string                                                         ni_dns_servers_;
#endif
#endif
                std::unique_ptr<route::RouteCoordinator>                            route_coordinator_;
                // A failed hosted-network apply that could not be fully
                // rolled back must not be followed by an Established state.
                bool                                                                hosted_routes_apply_failed_ = false;
                // Opened before the first hosted-network mutation so pending
                // state is replayed before a new DNS write is attempted.
                std::unique_ptr<NetworkRecoveryJournal>                             network_recovery_journal_;
                bool                                                                network_recovery_checked_ = false;
                // Set only after the complete startup worker has verified all
                // pre-existing records.  Current-session journal entries are
                // expected after this point and must not trigger a second
                // replay while the connection is applying its resources.
                bool                                                                network_recovery_ready_ = false;
                std::unique_ptr<AssignedAddressManager>                             address_manager_;
                std::unique_ptr<ClientConnectionTeardown>                           teardown_;
                std::atomic<bool>                                                   last_teardown_success_{true};
                std::unique_ptr<ClientConnectionOpener>                           connection_opener_;
                std::unique_ptr<ClientPacketDispatchHandler>                        packet_dispatch_;
                std::shared_ptr<xtcp::XtcpRuntime>                                  xtcp_runtime_;
                std::unique_ptr<ClientBypassRouteLoader>                          bypass_loader_;
                std::unique_ptr<PeerPrefixRouteManager>                         peer_prefix_routes_;
                std::unique_ptr<AggregatorLoader>                               aggregator_loader_;
                std::unique_ptr<RemoteEndpointLoader>                           remote_endpoint_loader_;
