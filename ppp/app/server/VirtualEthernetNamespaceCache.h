#pragma once 

#include <ppp/stdafx.h>
#include <ppp/collections/LinkedList.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetNamespaceCache : public std::enable_shared_from_this<VirtualEthernetNamespaceCache> {
                typedef std::mutex                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;

                typedef struct {        
                    uint64_t                                                expired_time;
                    ppp::string                                             queries_key;
                    std::shared_ptr<Byte>                                   response;
                    int                                                     response_length;
                }                                                           NamespaceRecord;
                typedef ppp::collections::LinkedListNode<NamespaceRecord>   NamespaceRecordNode;
                typedef std::shared_ptr<NamespaceRecordNode>                NamespaceRecordNodePtr;

            public:
                VirtualEthernetNamespaceCache(int ttl)                      noexcept;
                virtual ~VirtualEthernetNamespaceCache()                    noexcept;

            public:
                SynchronizedObject&                                         GetSynchronizedObject() noexcept { return LockObj_; }
                int                                                         GetTTL() const noexcept          { return TTL_; }
                static ppp::string                                          QueriesKey(uint16_t type, uint16_t clazz, const ppp::string& domain) noexcept;

            public:
                virtual bool                                                Add(const ppp::string& key, const std::shared_ptr<Byte>& response, int response_length) noexcept;
                virtual bool                                                Get(const ppp::string& key, std::shared_ptr<Byte>& response, int& response_length, uint16_t trans_id) noexcept;
                virtual void                                                Clear() noexcept;
                virtual void                                                Update() noexcept;

            private:    
                int                                                         TTL_ = 0;
                SynchronizedObject                                          LockObj_;
                ppp::unordered_map<ppp::string, NamespaceRecordNodePtr>     NamespaceHashTable_;
                ppp::collections::LinkedList<NamespaceRecord>               NamespaceLinkedList_;
            };
        }
    }
}