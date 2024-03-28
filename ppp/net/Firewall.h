#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/native/rib.h>

namespace ppp 
{
    namespace net 
    {
        class Firewall  
        {
        public:
            typedef std::mutex                                      SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
            typedef ppp::unordered_map<Int128, int>                 NetworkSegmentTable;
            typedef ppp::unordered_set<ppp::string>                 NetworkDomainsTable;

        public:
            virtual ~Firewall() noexcept = default;

        public:
            virtual bool                                            DropNetworkPort(int port) noexcept;
            virtual bool                                            DropNetworkPort(int port, bool tcp_or_udp) noexcept;
            virtual bool                                            DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept;
            virtual bool                                            DropNetworkDomains(const ppp::string& host) noexcept;
            virtual void                                            Clear() noexcept;
            bool                                                    LoadWithFile(const ppp::string& path) noexcept;
            virtual bool                                            LoadWithRules(const ppp::string& configuration) noexcept;

        public:
            virtual bool                                            IsDropNetworkPort(int port, bool tcp_or_udp) noexcept;
            virtual bool                                            IsDropNetworkDomains(const ppp::string& host) noexcept;
            virtual bool                                            IsDropNetworkSegment(const boost::asio::ip::address& ip) noexcept;

        public:
            static bool                                             IsSameNetworkDomains(const ppp::string& host, const ppp::function<bool(const ppp::string& s)>& contains) noexcept;

        private:
            SynchronizedObject                                      syncobj_;
            ppp::unordered_set<int>                                 ports_;
            ppp::unordered_set<int>                                 ports_tcp_;
            ppp::unordered_set<int>                                 ports_udp_;
            NetworkDomainsTable                                     network_domains_;
            NetworkSegmentTable                                     network_segments_;
        };
    }
}