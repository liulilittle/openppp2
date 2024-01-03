#pragma once

#include <ppp/stdafx.h>
#include <ppp/IDisposable.h>

namespace ppp {
    namespace collections {
        class Dictionary final {
        public:
            template <typename PredicateHandler, typename TObjects, typename... Args>
            static int                                              PredicateAllObjects(PredicateHandler&& predicate, TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                ppp::vector<TKey> release_object_keys;
                for (auto&& kv : objects) {
                    auto& obj = kv.second;
                    if (obj) {
                        if (predicate(obj, std::forward<Args&&>(args)...)) {
                            release_object_keys.emplace_back(kv.first);
                        }
                    }
                    else {
                        release_object_keys.emplace_back(kv.first);
                    }
                }

                for (auto&& object_key : release_object_keys) {
                    auto tail = objects.find(object_key);
                    auto endl = objects.end();
                    if (tail == endl) {
                        continue;
                    }

                    auto obj = std::move(tail->second);
                    objects.erase(tail);

                    IDisposable::Dispose(*obj);
                }
                return (int)release_object_keys.size();
            }

            template <typename TObjects, typename... Args>
            static int                                              UpdateAllObjects(TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type; 

                /* __cplusplus >= 201402L || _MSC_VER >= 1900 */
                return PredicateAllObjects(
                    [](TValue& obj, Args&& ...args) noexcept {
                        return obj->IsPortAging(std::forward<Args&&>(args)...);
                    }, objects, std::forward<Args&&>(args)...);
            }

            template <typename TObjects, typename... Args>
            static int                                              UpdateAllObjects2(TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                /* __cplusplus >= 201402L || _MSC_VER >= 1900 */
                return PredicateAllObjects(
                    [](TValue& obj, Args&& ...args) noexcept { /* cpp14: auto&&... */
                        return !obj->Update(std::forward<Args&&>(args)...);
                    }, objects, std::forward<Args&&>(args)...);
            }

            template <typename TObjects>
            static void                                             ReleaseAllObjects(TObjects& objects) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                if (IDisposable::HAS_MEMBER_DISPOSE_FUNCTION<typename std::remove_reference<decltype(**(TValue*)NULL)>::type>::value) {
                    ppp::vector<TValue> release_objects;
                    for (auto&& kv : objects) {
                        release_objects.emplace_back(std::move(kv.second));
                    }

                    objects.clear();
                    for (auto&& obj : release_objects) {
                        IDisposable::Dispose(*obj);
                    }
                }
                else {
                    objects.clear();
                }
            }

            template <typename TObjects>
            static typename TObjects::value_type::second_type       ReleaseObjectByKey(TObjects& objects, const typename TObjects::key_type& key) noexcept {
                typename TObjects::value_type::second_type obj{};

                auto tail = objects.find(key);
                auto endl = objects.end();
                if (tail != endl) {
                    obj = std::move(tail->second);
                    objects.erase(tail);
                }

                if (NULL != obj) {
                    IDisposable::Dispose(*obj);
                }
                return obj;
            }

            template <typename TObjects>
            static typename TObjects::value_type::second_type       FindObjectByKey(TObjects& objects, const typename TObjects::key_type& key) noexcept {
                auto tail = objects.find(key);
                auto endl = objects.end();
                if (tail == endl) {
                    return NULL;
                }
                else {
                    return tail->second;
                }
            }

        public:
            template <typename TCallbacks, typename... TArgs>
            static void                                             ReleaseAllCallbacks(TCallbacks& callbacks, TArgs&&... args) noexcept {
                ppp::vector<typename TCallbacks::value_type::second_type> list;
                for (auto&& kv : callbacks) {
                    list.emplace_back(std::move(kv.second));
                }

                callbacks.clear();
                for (auto&& weak : list) {
                    auto cb = weak.lock();
                    if (cb) {
                        (*cb)(std::forward<TArgs&&>(args)...);
                    }
                }
            }

        public:
            template <typename TDictionary>
            static bool                                             ContainsKey(TDictionary& dictionary, const typename TDictionary::key_type& key) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                return tail != endl;
            }

            template <typename TDictionary>
            static bool                                             RemoveValueByKey(TDictionary& dictionary, const typename TDictionary::key_type& key, typename TDictionary::value_type::second_type* value = NULL) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                if (tail != endl) {
                    if (NULL != value) {
                        *value = std::move(tail->second);
                    }

                    dictionary.erase(tail);
                    return true;
                }
                else {
                    return false;
                }
            }

            template <typename TResultValue, typename TDictionary, typename TFetchResult>
            static bool                                             RemoveValueByKey(TDictionary& dictionary, const typename TDictionary::key_type& key, TResultValue& result_value, TFetchResult&& fetch_result) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                if (tail != endl) {
                    result_value = fetch_result(tail->second);
                    dictionary.erase(tail);
                    return true;
                }
                else {
                    return false;
                }
            }
        };
    }
}