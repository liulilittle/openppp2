#pragma once

#include <stdio.h>
#include <stdint.h>

#include <utility>
#include <boost/asio.hpp>

struct sockaddr;

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace lsp
            {
                namespace paper_airplane
                {
#pragma pack(push, 1)
                    // The opening and closing of the paper plane session layer plug-in is controlled by shared memory, 
                    // Which is a global control block stored in the shared memory.
                    typedef struct
                    {
                        uint32_t            kf_1;
                        union
                        {
                            struct
                            {
                                int32_t     port;
                                int32_t     interface_index;
                                int32_t     process_id;
                            };
                            uint8_t         reserved[508];
                        };
                        uint32_t            kf_2;
                    } PaperAirplaneControlBlock;
#pragma pack(pop)

                    class PaperAirplaneControlBlockPort
                    {
                    public:
                        PaperAirplaneControlBlockPort() noexcept;
                        ~PaperAirplaneControlBlockPort() noexcept;

                    public:
                        bool                                    IsAvailable() noexcept;
                        std::pair<int, int>                     Get() noexcept;
                        bool                                    Set(int interface_index, int port) noexcept;

                    private:
                        void*                                   hMap;
                        void*                                   pBlock;
                    };

                    std::pair<int, int>                         GetBlock() noexcept;
                    std::pair<int, uint32_t>                    GetForwardPort(void* s, const struct sockaddr* name, int namelen) noexcept;
                    bool                                        PacketInput(
                        boost::asio::ip::tcp::socket&                                                                       socket, 
                        const std::function<int(boost::asio::ip::tcp::endpoint&, boost::asio::ip::tcp::endpoint&)>&         add_port_forward_handling);
                }
            }
        }
    }
}