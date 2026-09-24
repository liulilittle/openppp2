#include <ppp/stdafx.h>

#if defined(_ANDROID)

#include "OpenPPP2VpnProtectBridge.h"

#include <ppp/diagnostics/Error.h>

#include <android/log.h>

namespace ppp
{
    namespace android
    {
        namespace
        {
            constexpr const char* TAG = "OpenPPP2VpnProtect";

            class ProtectBridgeState final
            {
            public:
                JavaVM*                                             vm = NULLPTR;
                jclass                                              clazz = NULLPTR;
                jmethodID                                           protect = NULLPTR;
                jmethodID                                           is_ready = NULLPTR;
                bool                                                enabled = true;
                std::mutex                                          syncobj;
            };

            ProtectBridgeState& GetState() noexcept
            {
                static ProtectBridgeState state;
                return state;
            }

            bool ClearException(JNIEnv* env, const char* where) noexcept
            {
                if (NULLPTR == env || !env->ExceptionCheck())
                {
                    return false;
                }

                __android_log_print(ANDROID_LOG_WARN, TAG, "jni exception in %s", NULLPTR != where ? where : "unknown");
                env->ExceptionClear();
                return true;
            }

            JNIEnv* AttachEnvironment(JavaVM* vm, bool& attached) noexcept
            {
                attached = false;
                if (NULLPTR == vm)
                {
                    return NULLPTR;
                }

                JNIEnv* env = NULLPTR;
                jint result = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
                if (JNI_OK == result)
                {
                    return env;
                }

                if (JNI_EDETACHED != result)
                {
                    return NULLPTR;
                }

#if defined(__ANDROID__)
                if (JNI_OK != vm->AttachCurrentThread(&env, NULLPTR))
#else
                if (JNI_OK != vm->AttachCurrentThread(reinterpret_cast<void**>(&env), NULLPTR))
#endif
                {
                    return NULLPTR;
                }

                attached = true;
                return env;
            }

            bool CacheProtectClassLocked(ProtectBridgeState& state, JNIEnv* env) noexcept
            {
                if (NULLPTR == env)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    return false;
                }

                if (NULLPTR != state.clazz && NULLPTR != state.protect &&
                    NULLPTR != state.is_ready)
                {
                    return true;
                }

                jclass local_clazz = env->FindClass(LIBOPENPPP2_CLASSNAME);
                ClearException(env, "FindClass(" LIBOPENPPP2_CLASSNAME ")");
                if (NULLPTR == local_clazz)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                    __android_log_print(ANDROID_LOG_WARN, TAG, "class not found: %s", LIBOPENPPP2_CLASSNAME);
                    return false;
                }

                jmethodID protect_method = env->GetStaticMethodID(local_clazz, "protect", "(I)Z");
                ClearException(env, "GetStaticMethodID(protect)");
                if (NULLPTR == protect_method)
                {
                    env->DeleteLocalRef(local_clazz);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
                    __android_log_print(ANDROID_LOG_WARN, TAG, "method not found: protect(I)Z");
                    return false;
                }

                jmethodID ready_method = env->GetStaticMethodID(local_clazz, "isProtectReady", "()Z");
                ClearException(env, "GetStaticMethodID(isProtectReady)");
                if (NULLPTR == ready_method)
                {
                    env->DeleteLocalRef(local_clazz);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
                    __android_log_print(ANDROID_LOG_WARN, TAG, "method not found: isProtectReady()Z");
                    return false;
                }

                jclass global_clazz = static_cast<jclass>(env->NewGlobalRef(local_clazz));
                env->DeleteLocalRef(local_clazz);
                ClearException(env, "NewGlobalRef(protect class)");
                if (NULLPTR == global_clazz)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                if (NULLPTR != state.clazz)
                {
                    env->DeleteGlobalRef(state.clazz);
                }

                state.clazz = global_clazz;
                state.protect = protect_method;
                state.is_ready = ready_method;
                return true;
            }
        }

        bool InitializeProtectBridge(JavaVM* vm, JNIEnv* env) noexcept
        {
            if (NULLPTR == vm || NULLPTR == env)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                return false;
            }

            ProtectBridgeState& state = GetState();
            std::lock_guard<std::mutex> scope(state.syncobj);
            state.vm = vm;
            return CacheProtectClassLocked(state, env);
        }

        void ShutdownProtectBridge(JNIEnv* env) noexcept
        {
            ProtectBridgeState& state = GetState();
            JavaVM* vm = NULLPTR;
            jclass clazz = NULLPTR;
            bool attached = false;

            {
                std::lock_guard<std::mutex> scope(state.syncobj);
                vm = state.vm;
                clazz = state.clazz;
                state.clazz = NULLPTR;
                state.protect = NULLPTR;
                state.is_ready = NULLPTR;
                state.vm = NULLPTR;
                state.enabled = false;
            }

            if (NULLPTR == clazz)
            {
                return;
            }

            JNIEnv* release_env = env;
            if (NULLPTR == release_env)
            {
                release_env = AttachEnvironment(vm, attached);
            }

            if (NULLPTR != release_env)
            {
                release_env->DeleteGlobalRef(clazz);
            }

            if (attached && NULLPTR != vm)
            {
                vm->DetachCurrentThread();
            }
        }

        void SetProtectEnabled(bool value) noexcept
        {
            ProtectBridgeState& state = GetState();
            std::lock_guard<std::mutex> scope(state.syncobj);
            state.enabled = value;
        }

        bool IsProtectEnabled() noexcept
        {
            ProtectBridgeState& state = GetState();
            std::lock_guard<std::mutex> scope(state.syncobj);
            return state.enabled;
        }

        bool IsProtectBridgeReady() noexcept
        {
            ProtectBridgeState& state = GetState();
            JavaVM* vm = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(state.syncobj);
                if (!state.enabled)
                {
                    return false;
                }
                vm = state.vm;
            }

            bool attached = false;
            JNIEnv* env = AttachEnvironment(vm, attached);
            if (NULLPTR == env)
            {
                return false;
            }

            jboolean result = JNI_FALSE;
            {
                std::lock_guard<std::mutex> scope(state.syncobj);
                if (state.enabled && state.vm == vm &&
                    CacheProtectClassLocked(state, env))
                {
                    result = env->CallStaticBooleanMethod(state.clazz, state.is_ready);
                    if (ClearException(env, "CallStaticBooleanMethod(isProtectReady)"))
                    {
                        result = JNI_FALSE;
                    }
                }
            }

            if (attached)
            {
                vm->DetachCurrentThread();
            }
            return result == JNI_TRUE;
        }

        bool ProtectSocketFd(int fd) noexcept
        {
            if (fd < 0)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtectorNetworkProtectInvalidSocket);
                return false;
            }

            JavaVM* vm = NULLPTR;
            {
                ProtectBridgeState& state = GetState();
                std::lock_guard<std::mutex> scope(state.syncobj);
                if (!state.enabled)
                {
                    return false;
                }

                vm = state.vm;
            }

            bool attached = false;
            JNIEnv* env = AttachEnvironment(vm, attached);
            if (NULLPTR == env)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
                return false;
            }

            jclass clazz = NULLPTR;
            jmethodID protect_method = NULLPTR;
            {
                ProtectBridgeState& state = GetState();
                std::lock_guard<std::mutex> scope(state.syncobj);
                if (state.enabled && state.vm == vm &&
                    CacheProtectClassLocked(state, env))
                {
                    clazz = static_cast<jclass>(env->NewLocalRef(state.clazz));
                    ClearException(env, "NewLocalRef(protect class)");
                    protect_method = state.protect;
                }
            }

            jboolean result = JNI_FALSE;
            if (NULLPTR != clazz && NULLPTR != protect_method)
            {
                result = env->CallStaticBooleanMethod(clazz, protect_method, static_cast<jint>(fd));
                if (ClearException(env, "CallStaticBooleanMethod(protect)"))
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEventDispatchFailed);
                    result = JNI_FALSE;
                }
                env->DeleteLocalRef(clazz);
            }

            if (attached)
            {
                vm->DetachCurrentThread();
            }

            return result == JNI_TRUE;
        }
    }
}
#endif
