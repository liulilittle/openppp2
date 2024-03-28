#pragma once

#include <ppp/stdafx.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace dns
            {
                struct Rule final
                {
                public:
                    ppp::string                         Host;
                    bool                                Nic = false;
                    boost::asio::ip::address            Server;

                public:
                    typedef std::shared_ptr<Rule>       Ptr;

                public:
                    static Rule::Ptr                    Get(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;

                public:
                    static int                          Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                    static int                          LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                };
            }
        }
    }
}