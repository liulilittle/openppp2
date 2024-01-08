#include <ppp/diagnostics/Stopwatch.h>

#include <iostream>
#include <ctime>
#include <chrono>

// 煙花落寞後 月光沒照舊
// 揚長而去的春秋
// 我俯身將愛恨起伏再吹奏
// 擋住 被招攬的煩憂
// 炊煙繞一驟 最頑固念頭
// 一廂情願的不走
// 我轉身奔向漂泊中的渡口
// 忍住 嗆出聲的挽留
// 有幾分 冥冥之中緣由
// 我在等 沒等到的回頭
// 分明是寥寥輕舟
// 卻偏頗道沉重
// 是人還是離愁
// 有幾分 意料之外荒謬
// 你怪罪 一往情深不夠
// 我們沒走到最後
// 結局移到開頭
// 竟無處可追究

namespace ppp 
{
    namespace diagnostics
    {
        template <typename Duration>
        static constexpr int64_t ElapsedTimed(std::chrono::high_resolution_clock::time_point start, std::chrono::high_resolution_clock::time_point stop) noexcept
        {
            if (stop == std::chrono::high_resolution_clock::time_point())
            {
                stop = std::chrono::high_resolution_clock::now();
            }

            return std::chrono::duration_cast<Duration>(stop - start).count();
        }

        void Stopwatch::Start() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            std::chrono::high_resolution_clock::time_point null_;
            stop_ = null_;
            if (start_ == null_)
            {
                start_ = std::chrono::high_resolution_clock::now();
            }
        }

        void Stopwatch::Stop() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            std::chrono::high_resolution_clock::time_point null_;
            if (start_ == null_)
            {
                start_ = null_;
                stop_ = null_;
            }
            else
            {
                stop_ = std::chrono::high_resolution_clock::now();
            }
        }

        void Stopwatch::Reset() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            std::chrono::high_resolution_clock::time_point null_;
            start_ = null_;
            stop_ = null_;
        }

        void Stopwatch::Restart() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            start_ = std::chrono::high_resolution_clock::now();
            stop_ = std::chrono::high_resolution_clock::time_point();
        }

        int64_t Stopwatch::ElapsedMilliseconds() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            return ElapsedTimed<std::chrono::milliseconds>(start_, stop_);
        }

        int64_t Stopwatch::ElapsedTicks() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            return ElapsedTimed<std::chrono::nanoseconds>(start_, stop_);
        }

        bool Stopwatch::IsRunning() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            std::chrono::high_resolution_clock::time_point null_;
            return start_ != null_ && stop_ == null_;
        }

        DateTime Stopwatch::Elapsed() noexcept
        {
            int64_t ms = ElapsedMilliseconds();
            return DateTime::MinValue().AddMilliseconds(ms);
        }
    }
}