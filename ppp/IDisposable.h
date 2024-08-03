#pragma once

#include <ppp/Reference.h>

namespace ppp {
    class IDisposable : public Reference {
    public:
        template <typename T>
        struct HAS_MEMBER_DISPOSE_FUNCTION final {
        private:
            template <typename U>
            static auto                         SFINAE_TEST(T*) noexcept -> decltype(std::declval<U>().Dispose(), std::true_type());

            template <typename U>
            static std::false_type              SFINAE_TEST(...) noexcept;

        public:
            static constexpr bool               value = decltype(SFINAE_TEST<T>(NULL))::value;
        };

        template <typename T>
        static bool                             Dispose(const T& obj) noexcept { /* CXX11: typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type */
            if constexpr (std::is_pointer<T>::value) {
                return DISPOSE_NPTR(obj);
            }
            elif constexpr (stl::is_shared_ptr<T>::value) {
                return DISPOSE_SPTR(obj);
            }
            elif constexpr (stl::is_unique_ptr<T>::value) {
                return DISPOSE_UPTR(constantof(obj));
            }
            elif constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                return DISPOSE_COBJ(constantof(obj));
            }
            else {
                return false;
            }
        }

        template <class... TReferences>
        static void                             DisposeReferences(TReferences&&... objects) noexcept {
            (IDisposable::Dispose(objects), ...);
        }

    public:
        virtual void                            Dispose() noexcept = 0;
        virtual                                 ~IDisposable() noexcept = default;

    private:
        template <typename T>
        static bool                             DISPOSE_COBJ(T& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                obj.Dispose();
                return true;
            }

            return false;
        }

        template <typename T>
        static bool                             DISPOSE_NPTR(T* obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }
            return false;
        }

        template <typename T>
        static bool                             DISPOSE_SPTR(const std::shared_ptr<T>& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }

            return false;
        }

        template <typename T>
        static bool                             DISPOSE_UPTR(const std::unique_ptr<T>& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }
            
            return false;
        }
    };
}