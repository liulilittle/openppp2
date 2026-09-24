#pragma once

#include <ppp/stdafx.h>

#if defined(_ANDROID)
#include <jni.h>

namespace ppp
{
    namespace android
    {
        /**
         * @brief Initializes the Android VpnService.protect(fd) JNI bridge.
         *
         * The default Java endpoint is:
         *   supersocksr.ppp.android.c.libopenppp2.protect(int): boolean
         *
         * Android app integrations may keep that static method as a thin wrapper
         * around VpnService.protect(fd).  This bridge intentionally only exposes
         * native C++ entry points; it does not change DNS resolver transport paths.
         */
        bool                                                            InitializeProtectBridge(JavaVM* vm, JNIEnv* env) noexcept;

        /** @brief Releases cached global JNI references held by the bridge. */
        void                                                            ShutdownProtectBridge(JNIEnv* env = NULLPTR) noexcept;

        /** @brief Enables or disables native calls into Java protect(int). */
        void                                                            SetProtectEnabled(bool value) noexcept;

        /** @brief Returns whether native calls into Java protect(int) are enabled. */
        bool                                                            IsProtectEnabled() noexcept;

        /** @brief Returns whether the JNI bridge and active VpnService are ready. */
        bool                                                            IsProtectBridgeReady() noexcept;

        /**
         * @brief Protects a native socket fd by calling the cached Java protect(int).
         *
         * Safe from arbitrary native threads.  Threads not attached to the JVM are
         * attached for the duration of the call and detached before returning.
         */
        bool                                                            ProtectSocketFd(int fd) noexcept;
    }
}
#endif
