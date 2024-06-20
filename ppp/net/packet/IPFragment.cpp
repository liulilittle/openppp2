#include <ppp/net/packet/IPFragment.h>
#include <ppp/io/Stream.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/collections/Dictionary.h>

using ppp::io::MemoryStream;
using ppp::net::packet::IPFlags;
using ppp::net::packet::IPFrame;
using ppp::net::packet::BufferSegment;

namespace ppp {
    namespace net {
        namespace packet {
            static Int128 FragmentKey(const std::shared_ptr<IPFrame>& packet) noexcept {
                Int128 key = (Int128)packet->Source;
                key = key | ((Int128)packet->Destination) << 32;
                key = key | ((Int128)packet->Id) << 64;
                return true;
            }

            bool IPFragment::Input(const std::shared_ptr<IPFrame>& packet) noexcept {
                if ((packet->Flags & IPFlags::IP_MF) != 0 || ((packet->Flags & IPFlags::IP_OFFMASK) != 0 && packet->GetFragmentOffset() > 0)) {
                    std::shared_ptr<BufferSegment> payload = packet->Payload;
                    if (NULL == payload || payload->Length <= 0) {
                        return false;
                    }

                    IPFramePtr originNew;
                    Int128 key = FragmentKey(packet);
                    do {
                        std::shared_ptr<Subpackage> subpackage; {
                            SynchronizedObjectScope scope(syncobj_);
                            
                            SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.find(key);
                            SubpackageTable::iterator endl = IPV4_SUBPACKAGES_.end();
                            if (tail != endl) {
                                subpackage = tail->second;
                            }
                            else {
                                subpackage = make_shared_object<Subpackage>();
                                if (NULL == subpackage) {
                                    return false;
                                }

                                IPV4_SUBPACKAGES_.emplace(SubpackageTable::value_type(key, subpackage));
                            }
                        }

                        ppp::vector<IPFramePtr>& frames = subpackage->Frames;
                        size_t index = frames.size();
                        if (index <= 0) {
                            frames.emplace_back(packet);
                        }
                        else {
                            while (index > 0) {
                                IPFramePtr left = frames[index - 1];
                                if (packet->GetFragmentOffset() >= left->GetFragmentOffset()) {
                                    break;
                                }
                                else {
                                    index--;
                                }
                            }
                            frames.emplace(frames.begin() + index, packet);
                        }

                        int nextFragementOffset = 0;
                        bool fullFragementOffset = true; {
                            size_t count = frames.size();
                            for (index = 0; index < count; index++) {
                                IPFramePtr left = frames[index];
                                if (left->GetFragmentOffset() != nextFragementOffset) {
                                    fullFragementOffset = false;
                                    break;
                                }
                                else {
                                    nextFragementOffset = left->GetFragmentOffset() + left->Payload->Length;
                                }
                            }

                            if (fullFragementOffset) {
                                IPFramePtr left = frames[frames.size() - 1];
                                if ((packet->Flags & IPFlags::IP_MF) == 0 &&
                                    (packet->Flags & IPFlags::IP_OFFMASK) != 0 && left->GetFragmentOffset() > 0) {
                                    left = frames[0]; {
                                        SynchronizedObjectScope scope(syncobj_);
                                        
                                        SubpackageTable::iterator tail = IPV4_SUBPACKAGES_.find(key);
                                        SubpackageTable::iterator endl = IPV4_SUBPACKAGES_.end();
                                        if (tail != endl) {
                                            IPV4_SUBPACKAGES_.erase(tail);
                                        }
                                    }

                                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                                    std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, nextFragementOffset);
                                    if (NULL == buffer) {
                                        return false;
                                    }

                                    MemoryStream ms(buffer, nextFragementOffset);
                                    for (index = 0, count = frames.size(); index < count; index++) {
                                        std::shared_ptr<BufferSegment> payload = frames[index]->Payload;
                                        ms.Write(payload->Buffer.get(), 0, payload->Length);
                                    }

                                    originNew = make_shared_object<IPFrame>();
                                    if (NULL == originNew) {
                                        return false;
                                    }

                                    std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(buffer, nextFragementOffset);
                                    if (NULL == packet_payload) {
                                        return false;
                                    }
                                    
                                    originNew->AddressesFamily = left->AddressesFamily;
                                    originNew->ProtocolType = left->ProtocolType;
                                    originNew->Source = left->Source;
                                    originNew->Destination = left->Destination;
                                    originNew->Payload = packet_payload;
                                    originNew->Id = left->Id;
                                    originNew->Options = left->Options;
                                    originNew->Tos = left->Tos;
                                    originNew->Ttl = left->Ttl;
                                    originNew->Flags = IPFlags::IP_DF;
                                    originNew->SetFragmentOffset(0);
                                }
                            }
                        }
                    } while (false);

                    if (NULL != originNew) {
                        PacketInputEventArgs e{ originNew };
                        OnInput(e);
                    }
                    return true;
                }
                else {
                    return false;
                }
            }

            bool IPFragment::Output(const IPFrame* packet) noexcept {
                typedef std::shared_ptr<BufferSegment>   Buffer;

                IPFrame* const frame = constantof(packet);
                if (NULL == frame) {
                    return false;
                }

                while (0 == packet->Id) {
                    frame->Id = IPFrame::NewId();
                }

                ppp::vector<IPFramePtr> subpackages;
                int subpacketl = IPFrame::Subpackages(subpackages, std::shared_ptr<IPFrame>(frame, [](const IPFrame*) noexcept {}));
                if (subpacketl <= 0) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                for (int i = 0; i < subpacketl; i++) {
                    IPFramePtr frame_ = subpackages[i];
                    if (NULL == frame_) {
                        return false;
                    }

                    Buffer message_ = frame_->ToArray(allocator);
                    if (NULL == message_ || message_->Length <= 0) {
                        return false;
                    }

                    PacketOutputEventArgs e{ message_->Buffer, message_->Length };
                    OnOutput(e);
                }
                return true;
            }

            void IPFragment::Release() noexcept {
                PacketInput.reset();
                PacketOutput.reset();

                SynchronizedObjectScope scope(syncobj_);
                IPV4_SUBPACKAGES_.clear();
            }

            int IPFragment::Update(uint64_t now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return ppp::collections::Dictionary::PredicateAllObjects(
                    [now](const Subpackage::Ptr& subpackage) noexcept {
                        return now >= subpackage->FinalizeTime || 
                            (subpackage->FinalizeTime > Subpackage::MAX_FINALIZE_TIME && now <= Subpackage::MAX_FINALIZE_TIME);
                    }, IPV4_SUBPACKAGES_);
            }

            void IPFragment::OnInput(PacketInputEventArgs& e) noexcept {
                PacketInputEventHandler eh = PacketInput;
                if (eh) {
                    eh(this, e);
                }
            }

            void IPFragment::OnOutput(PacketOutputEventArgs& e) noexcept {
                PacketOutputEventHandler eh = PacketOutput;
                if (eh) {
                    eh(this, e);
                }
            }
        }
    }
}