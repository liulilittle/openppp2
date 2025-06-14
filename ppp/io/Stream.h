#pragma once

#include <ppp/stdafx.h>
#include <ppp/io/SeekOrigin.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace io {
        class Stream {
        public:
            std::shared_ptr<ppp::threading::BufferswapAllocator>    BufferAllocator;

        public:
            virtual bool                                            CanSeek() = 0;
            virtual bool                                            CanRead() = 0;
            virtual bool                                            CanWrite() = 0;

        public:
            virtual int                                             GetPosition() = 0;
            virtual int                                             GetLength() = 0;
            virtual bool                                            Seek(int offset, SeekOrigin loc) = 0;
            virtual bool                                            SetPosition(int position)  = 0;
            virtual bool                                            SetLength(int value) = 0;

        public:
            virtual bool                                            WriteByte(Byte value) = 0;
            virtual bool                                            Write(const void* buffer, int offset, int count) = 0;

        public:
            virtual int                                             ReadByte() = 0;
            virtual int                                             Read(const void* buffer, int offset, int count) = 0;

        public:
            virtual void                                            Dispose() = 0;
        };
    }
}