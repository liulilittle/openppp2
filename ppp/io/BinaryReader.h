#pragma once

#include <ppp/stdafx.h>
#include <ppp/io/Stream.h>

namespace ppp {
    namespace io {
        class BinaryReader {
        public:
            BinaryReader(Stream& stream) noexcept
                : _stream(stream) {

            }

        public:
            int                                             Read(const void* buffer, int offset, int length) noexcept {
                return _stream.Read(buffer, offset, length);
            }
                    
            template <typename TValueType>           
            std::shared_ptr<TValueType>                     ReadValues(int counts) noexcept {
                if (counts < 1) {
                    return NULL;
                }

                std::shared_ptr<TValueType> buf;
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = _stream.BufferAllocator;
                if (NULL != allocator) {
                    buf = allocator->MakeArray<TValueType>(counts);
                }
                else {
                    buf = make_shared_alloc<TValueType>(counts);
                }

                if (NULL == buf) {
                    return NULL;
                }

                int size = counts * sizeof(TValueType);
                int len = _stream.Read(buf.get(), 0, size);
                if (len < 0 || len != size) {
                    return NULL;
                }
                return buf;
            }
                    
            std::shared_ptr<Byte>                           ReadBytes(int counts) noexcept {
                return ReadValues<Byte>(counts);
            }
                    
            template <typename TValueType>           
            bool                                            TryReadValue(TValueType& out) noexcept {
                TValueType* p = (TValueType*)&reinterpret_cast<const char&>(out);
                int len = _stream.Read(p, 0, sizeof(TValueType));
                return (size_t)len == sizeof(TValueType);
            }
                    
            template <typename TValueType>                   
            TValueType                                      ReadValue() {
                TValueType out;
                if (!TryReadValue(out)) {
                    throw std::runtime_error("Unable to read from stream to TValueType size values");
                }
                return out;
            }
                    
            Stream&                                         GetStream() noexcept { return _stream; }

        public:
            Int16                                           ReadInt16() noexcept { return ReadValue<Int16>(); }
            Int32                                           ReadInt32() noexcept { return ReadValue<Int32>(); }
            Int64                                           ReadInt64() noexcept { return ReadValue<Int64>(); }
            UInt16                                          ReadUInt16() noexcept { return ReadValue<UInt16>(); }
            UInt32                                          ReadUInt32() noexcept { return ReadValue<UInt32>(); }
            UInt64                                          ReadUInt64() noexcept { return ReadValue<UInt64>(); }
            SByte                                           ReadSByte() noexcept { return ReadValue<SByte>(); }
            Byte                                            ReadByte() noexcept { return ReadValue<Byte>(); }
            Single                                          ReadSingle() noexcept { return ReadValue<Single>(); }
            Double                                          ReadDouble() noexcept { return ReadValue<Double>(); }
            bool                                            ReadBoolean() noexcept { return ReadValue<bool>(); }
            Char                                            ReadChar() noexcept { return ReadValue<Char>(); }

        public:     
            bool                                            TryReadInt16(Int16& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadInt32(Int32& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadInt64(Int64& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadUInt16(UInt16& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadUInt32(UInt32& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadUInt64(UInt64& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadSByte(SByte& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadByte(Byte& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadSingle(Single& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadDouble(bool& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadBoolean(bool& out) noexcept { return TryReadValue(out); }
            bool                                            TryReadChar(Char& out) noexcept { return TryReadValue(out); }

        private:            
            Stream&                                         _stream;
        };
    }
}