#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                FixUnderlyingNgw() noexcept;
#endif
                route::RoutePlanInput                                               BuildRoutePlanInput() noexcept;

                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;
                bool                                                                DeleteTimeout(void* k) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                TryApplyHostedNetworkRoutes() noexcept;
#else
                bool                                                                TryApplyHostedNetworkRoutes() noexcept { return true; }
#endif

                void                                                                DisposeAttempt(ppp::function<void(bool)> completion, int attempts_remaining) noexcept;
                void                                                                ReleaseAllObjects() noexcept;
                void                                                                ReleaseAllPackets() noexcept;
                void                                                                ReleaseAllTimeouts() noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_WIN32)
                bool                                                                UsePaperAirplaneController() noexcept;
                bool                                                                BindWindowsIPv6RouteOwner() noexcept;
                bool                                                                StageWindowsIPv6Egress(const boost::asio::ip::tcp::endpoint& endpoint, bool proven_external) noexcept;
                bool                                                                EnsureWindowsIPv6Sink() noexcept;
                bool                                                                ActivateWindowsManagedIPv6(const boost::asio::ip::address& gateway, bool nat_mode) noexcept;
                bool                                                                CommitWindowsIPv6Egress() noexcept;
                bool                                                                RollbackWindowsIPv6Egress() noexcept;
                bool                                                                StopWindowsIPv6Routes() noexcept;
                bool                                                                HasActiveWindowsIPv6Takeover() const noexcept;
                bool                                                                HasPendingWindowsIPv6Cleanup() const noexcept;
#endif
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                void                                                                Finalize() noexcept;
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                bool                                                                StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv6() noexcept;
                bool                                                                ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv4() noexcept;
#endif

                bool                                                                ERORTE(int ack_id) noexcept;
                bool                                                                PreparedAggregator() noexcept;
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept;
