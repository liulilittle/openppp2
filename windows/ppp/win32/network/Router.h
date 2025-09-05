#pragma once

#include <ppp/stdafx.h>

#include <Windows.h>
#include <Iphlpapi.h>

namespace ppp
{
    namespace win32
    {
        namespace network
        {
            class Router final
            {
            public:
                static int                                  GetBestInterface(uint32_t ip) noexcept;
                static bool                                 GetBestRoute(uint32_t destination, MIB_IPFORWARDROW& route) noexcept;
                static bool                                 GetBestRoute(uint32_t destination, uint32_t source, MIB_IPFORWARDROW& route) noexcept;
                static std::shared_ptr<MIB_IPFORWARDTABLE>  GetIpForwardTable() noexcept;

            public:
                static int                                  Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t mask, uint32_t gw, int interface_index) noexcept;
                static int                                  Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t mask, uint32_t gw) noexcept;
                static int                                  Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, uint32_t gw) noexcept;
                static int                                  Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination) noexcept;
                static int                                  Delete(const std::shared_ptr<MIB_IPFORWARDTABLE>& table, uint32_t destination, int interface_index) noexcept;
                static bool                                 Delete(MIB_IPFORWARDROW& route) noexcept;

            public:
                static bool                                 Add(uint32_t destination, uint32_t gw, int metric) noexcept;
                static bool                                 Add(uint32_t destination, uint32_t mask, uint32_t gw, int metric) noexcept;
                static bool                                 Add(uint32_t destination, uint32_t mask, uint32_t gw, int metric, int interface_index) noexcept;
                static bool                                 Add(MIB_IPFORWARDROW& route) noexcept;
            };
        }
    }
}