#pragma once

#include <ppp/Reference.h>

namespace ppp {
    class IDisposable : public Reference {
    public:
        template <typename T>
        struct HAS_MEMBER_DISPOSE_FUNCTION {
        private:
            template<typename U>
            static auto                         SFINAE_TEST(T*) -> decltype(std::declval<U>().Dispose(), std::true_type());

            template<typename U>
            static std::false_type              SFINAE_TEST(...);

        public:
            static constexpr bool               value = decltype(SFINAE_TEST<T>(NULL))::value;
        };

        template <typename T>
        typename std::enable_if<!HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type
        static constexpr                        Dispose(T& obj) noexcept { return false; }

        template <typename T>
        typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type
        static                                  Dispose(const std::shared_ptr<T>& obj) noexcept {
            if (obj) {
                obj->Dispose();
                return obj;
            }
            return false;
        }

        template <typename T>
        typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type
        static                                  Dispose(const std::unique_ptr<T>& obj) noexcept {
            if (obj) {
                obj->Dispose();
                return obj;
            }
            return false;
        }

        template <typename T>
        typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type
        static                                  Dispose(T& obj) noexcept {
            obj.Dispose();
            return true;
        }

        template <typename T>
        typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type
        static                                  Dispose(T* obj) noexcept {
            if (obj) {
                obj->Dispose();
                return true;
            }
            return true;
        }

        template <class... TReferences>
        static void                             DisposeReferences(TReferences&&... objects) noexcept {
            (IDisposable::Dispose(objects), ...);
        }
        
    public:
        virtual void                            Dispose() noexcept = 0;
        virtual                                 ~IDisposable() noexcept = default;
    };
}