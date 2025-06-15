#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    class Reference : public std::enable_shared_from_this<Reference> {
    public:
        Reference() noexcept = default;
        virtual ~Reference() noexcept = default;

    public:
        std::shared_ptr<Reference>                      GetReference() const noexcept {
            Reference* my = constantof(this);
            return my->shared_from_this();
        }

    public:
        template <typename _Ty1, typename _Ty2>
        static std::shared_ptr<_Ty1>                    AsReference(const std::shared_ptr<_Ty2>& v) noexcept {
            return v ? std::dynamic_pointer_cast<_Ty1>(v) : NULL;
        }

    public:
        template <typename _Ty1, typename _Ty2>
        static std::shared_ptr<_Ty1>                    CastReference(const std::shared_ptr<_Ty2>& v) noexcept {
            if (!v) {
                return NULL;
            }

            _Ty2* native_pTy2 = constantof(v.get());
            _Ty1* native_pTy1 = static_cast<_Ty1*>(native_pTy2);

            const std::shared_ptr<_Ty2> shared_pTy2 = v;
            return std::shared_ptr<_Ty1>(native_pTy1, [shared_pTy2](const void*) noexcept {});
        }

    public:
        template <class _Ty1 = Reference, class _Ty2 = Reference, typename... A>
        static std::shared_ptr<_Ty1>                    NewReference2(A&&... args) noexcept {
            static_assert(sizeof(_Ty1) > 0 && sizeof(_Ty2) > 0, "can't make pointer to incomplete type");

            void* memory = Malloc(sizeof(_Ty2));
            if (NULL == memory) {
                return NULL;
            }

            memset(memory, 0, sizeof(_Ty2));
            return std::shared_ptr<_Ty1>(new (memory) _Ty2(std::forward<A&&>(args)...),
                [](_Ty2* p) noexcept {
                    p->~_Ty2();
                    Mfree(p);
                });
        }

        template <class _Ty1 = Reference, typename... A>
        static std::shared_ptr<_Ty1>                    NewReference(A&&... args) noexcept {
            return NewReference2<_Ty1, _Ty1>(std::forward<A&&>(args)...);
        }
    };
}