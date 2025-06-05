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
                    static Rule::Ptr                    Get(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                    static int                          Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                    static int                          LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                
                private:
                    static Rule::Ptr                    GetWithRegExp(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                    static Rule::Ptr                    GetWithRelativePath(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                    static Rule::Ptr                    GetWithAbsoluteHost(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                };
            }
        }
    }
}