#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            class IPFragment {
            private:
                typedef std::shared_ptr<IPFrame>                                    IPFramePtr;
                struct Subpackage {
                public:
                    typedef std::shared_ptr<Subpackage>                             Ptr;

                public:
                    Subpackage() noexcept : FinalizeTime(ppp::threading::Executors::GetTickCount() + Subpackage::MAX_FINALIZE_TIME) {}

                public:
                    UInt64                                                          FinalizeTime = 0;
                    ppp::vector<IPFramePtr>                                         Frames;

                public:
                    static const int                                                MAX_FINALIZE_TIME = 1;
                };
                typedef ppp::unordered_map<Int128, Subpackage::Ptr>                 SubpackageTable;

            public:
                typedef std::mutex                                                  SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;
                typedef struct {
                    IPFramePtr                                                      Packet;
                }                                                                   PacketInputEventArgs;
                typedef ppp::function<void(IPFragment*, PacketInputEventArgs&)>     PacketInputEventHandler;
                typedef struct {
                    std::shared_ptr<Byte>                                           Packet;
                    int                                                             PacketLength;
                }                                                                   PacketOutputEventArgs;
                typedef ppp::function<void(IPFragment*, PacketOutputEventArgs&)>    PacketOutputEventHandler;

            public:
                PacketInputEventHandler                                             PacketInput;
                PacketOutputEventHandler                                            PacketOutput;
                std::shared_ptr<ppp::threading::BufferswapAllocator>                BufferAllocator;

            public:
                virtual bool                                                        Input(const std::shared_ptr<IPFrame>& packet) noexcept;
                virtual bool                                                        Output(const IPFrame* packet) noexcept;
                virtual int                                                         Update(uint64_t now) noexcept;
                virtual void                                                        Release() noexcept;

            protected:
                virtual void                                                        OnInput(PacketInputEventArgs& e) noexcept;
                virtual void                                                        OnOutput(PacketOutputEventArgs& e) noexcept;

            private:
                SynchronizedObject                                                  syncobj_;
                SubpackageTable                                                     IPV4_SUBPACKAGES_;
            };
        }
    }
}