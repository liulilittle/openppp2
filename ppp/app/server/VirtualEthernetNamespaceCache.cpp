#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>

namespace ppp {
    namespace app {
        namespace server {
            using ppp::threading::Executors;
            using ppp::collections::Dictionary;

            VirtualEthernetNamespaceCache::VirtualEthernetNamespaceCache(int ttl) noexcept {
                if (ttl < 1) {
                    ttl = 60;
                }

                uint64_t qw = static_cast<uint64_t>(ttl) * 1000ULL;
                if (qw > INT32_MAX) {
                    qw = INT32_MAX;
                }

                TTL_ = static_cast<int>(qw);
            }

            VirtualEthernetNamespaceCache::~VirtualEthernetNamespaceCache() noexcept {
                NamespaceHashTable_.clear();
                NamespaceLinkedList_.Clear();
            }

            ppp::string VirtualEthernetNamespaceCache::QueriesKey(uint16_t type, uint16_t clazz, const ppp::string& domain) noexcept {
                ppp::string queries_key = "TYPE:" +
                    stl::to_string<ppp::string>(type) + "|CLASS:" +
                    stl::to_string<ppp::string>(clazz) + "|DOMAIN:" + domain;
                return queries_key;
            }

            bool VirtualEthernetNamespaceCache::Add(const ppp::string& key, const std::shared_ptr<Byte>& response, int response_length) noexcept {
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (key.empty()) { /* min heap. */
                    return false;
                }

                if (NULL == response) {
                    return false;
                }

                if (response_length < sizeof(dns_hdr)) {
                    return false;
                }

                NamespaceRecordNodePtr node;
                SynchronizedObjectScope scope(LockObj_);

                if (Dictionary::TryRemove(NamespaceHashTable_, key, node)) {
                    NamespaceLinkedList_.Remove(node);
                }
                else {
                    node = make_shared_object<NamespaceRecordNode>();
                    if (NULL == node) {
                        return false;
                    }
                }

                NamespaceRecord& record = node->Value;
                record.queries_key      = key;
                record.response         = response;
                record.response_length  = response_length;
                record.expired_time     = Executors::GetTickCount() + TTL_;

                if (Dictionary::TryAdd(NamespaceHashTable_, key, node)) {
                    bool b = NamespaceLinkedList_.AddLast(node);
                    if (!b) {
                        Dictionary::TryRemove(NamespaceHashTable_, key);
                    }

                    return b;
                }

                return false;
            }

            void VirtualEthernetNamespaceCache::Update() noexcept {
                NamespaceRecordNodePtr node;
                SynchronizedObjectScope scope(LockObj_);

                node = NamespaceLinkedList_.First();
                if (NULL != node) {
                    uint64_t now = Executors::GetTickCount();
                    do {
                        NamespaceRecord& record = node->Value;
                        if (now < record.expired_time) {
                            break;
                        }

                        if (!Dictionary::TryRemove(NamespaceHashTable_, record.queries_key)) {
                            break;
                        }

                        NamespaceRecordNodePtr next = node->Next;
                        NamespaceLinkedList_.Remove(node);
                        node = next;
                    } while (NULL != node);
                }
            }

            bool VirtualEthernetNamespaceCache::Get(const ppp::string& key, std::shared_ptr<Byte>& response, int& response_length, uint16_t trans_id) noexcept {
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (key.empty()) {
                    return false;
                }
                else {
                    NamespaceRecordNodePtr node;
                    SynchronizedObjectScope scope(LockObj_);

                    if (!Dictionary::TryGetValue(NamespaceHashTable_, key, node)) {
                        return false;
                    }

                    if (NULL == node) {
                        Dictionary::TryRemove(NamespaceHashTable_, key);
                        return false;
                    }

                    NamespaceRecord& record = node->Value;
                    response                = record.response;
                    response_length         = record.response_length;
                }

                if (response_length < sizeof(dns_hdr)) {
                    return false;
                }

                ((dns_hdr*)response.get())->usTransID = trans_id;
                return true;
            }

            void VirtualEthernetNamespaceCache::Clear() noexcept {
                SynchronizedObjectScope scope(LockObj_);
                NamespaceHashTable_.clear();
                NamespaceLinkedList_.Clear();
            }
        }
    }
}