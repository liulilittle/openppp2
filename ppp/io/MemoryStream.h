#pragma once 

#include <string.h>
#include <limits.h>
#include <ppp/stdafx.h>
#include <ppp/io/Stream.h>

#ifndef __INT_MAX__
#define __INT_MAX__ 2147483647
#endif

namespace ppp {
    namespace io {
        class MemoryStream : public Stream {
        public:
            MemoryStream() noexcept
                : MemoryStream(0) {

            }
            MemoryStream(int capacity) noexcept
                : _expandable(true)
                , _disposed(false)
                , _position(0)
                , _length(0)
                , _capacity(0) {
                if (capacity > 0) {
                    this->SetCapacity(capacity);
                }
            }
            MemoryStream(const std::shared_ptr<Byte>& buffer, int count) noexcept
                : _expandable(false)
                , _disposed(false)
                , _position(0)
                , _length(count)
                , _capacity(count)
                , _buffer(buffer) {
                
            }

        public:
            virtual bool                        CanSeek() noexcept override { return true; }
            virtual bool                        CanRead() noexcept override { return true; }
            virtual bool                        CanWrite() noexcept override { return true; }

        public:
            virtual int                         GetPosition() noexcept override { return this->_position; }
            virtual int                         GetLength() noexcept override { return this->_length; }
            virtual int                         GetCapacity() noexcept { return this->_capacity - this->_length; }

        public:         
            virtual bool                        Seek(int offset, SeekOrigin loc) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                switch (loc) {
                case SeekOrigin::Begin: {
                    int now = offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }

                    this->_position = offset;
                    break;
                }
                case SeekOrigin::Current: {
                    int now = this->_position + offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }
                    
                    this->_position = now;
                    break;
                }
                case SeekOrigin::End: {
                    int now = this->_length + offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }

                    this->_position = now;
                    break;
                }
                default:
                    return false;
                }
                return true;
            }
            virtual bool                        SetPosition(int position) noexcept override { return this->Seek(position, SeekOrigin::Begin); }
            virtual bool                        SetLength(int value) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                if (value < 0) {
                    return false;
                }

                if (!this->EnsureCapacity(value)) {
                    return false;
                }

                this->_length = value;
                if (this->_position > value) {
                    this->_position = value;
                }
                return true;
            }
            virtual bool                        SetCapacity(int value) noexcept {
                if (this->_disposed) {
                    return false;
                }

                if (value < this->_length) {
                    return false;
                }

                if (!this->_expandable && value != this->_capacity) {
                    return false;
                }

                if (!this->_expandable || value == this->_capacity) {
                    return true;
                }

                if (value > 0) {
                    std::shared_ptr<Byte> array = this->NewBuffer(value);
                    if (this->_length > 0) {
                        memcpy(array.get(), this->_buffer.get(), this->_length);
                    }

                    this->_buffer = array;
                }
                else {
                    this->_buffer = NULL;
                }

                this->_capacity = value;
                return true;
            }
            virtual void                        Dispose() noexcept override {
                if (!this->_disposed) {
                    this->_expandable = false;
                    this->_position = 0;
                    this->_length = 0;
                    this->_capacity = 0;
                    this->_buffer = NULL;
                    this->_disposed = true;
                }
            }     

        public:
            virtual bool                        WriteByte(Byte value) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                int num = this->_position + 1;
                if (num > this->_length) {
                    if (!this->EnsureCapacity(num)) {
                        return false;
                    }

                    this->_length = num;
                }

                this->_buffer.get()[this->_position++] = value;
                return true;
            }
            virtual bool                        Write(const void* buffer, int offset, int count) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                if (NULL == buffer) {
                    if (offset == 0 && count == 0) {
                        return true;
                    }
                    return false;
                }

                if (offset < 0) {
                    return false;
                }

                if (count < 0) {
                    return false;
                }

                if (count == 0) {
                    return true;
                }

                int num = this->_position + count;
                if (num > this->_length) {
                    if (!this->EnsureCapacity(num)) {
                        return false;
                    }
                    
                    this->_length = num;
                }

                memcpy(this->_buffer.get() + this->_position, (char*)buffer + offset, count);
                this->_position = num;
                return true;
            }                                

        public:
            virtual int                         ReadByte() noexcept override {
                if (this->_disposed) {
                    return false;
                }

                if (this->_position >= this->_length) {
                    return -1;
                }

                return this->_buffer.get()[this->_position++];
            }
            virtual int                         Read(const void* buffer, int offset, int count) noexcept override {
                if (this->_disposed) {
                    return -1;
                }

                if (NULL == buffer) {
                    if (offset == 0 && count == 0) {
                        return 0;
                    }
                    return -1;
                }

                if (offset < 0) {
                    return -1;
                }

                if (count < 0) {
                    return -1;
                }
                elif (count == 0) {
                    return 0;
                }

                int num = this->_length - this->_position;
                if (num > count) {
                    num = count;
                }

                if (num < 1) {
                    return 0;
                }

                memcpy((char*)buffer + offset, this->_buffer.get() + this->_position, num);
                this->_position += num;
                return num;
            }

        public:
            std::shared_ptr<Byte>               GetBuffer() const noexcept { return this->_buffer; }
            std::shared_ptr<Byte>               ToArray(int& length) noexcept {
                length = this->_length;
                if (length < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> dest = this->NewBuffer(length);
                if (NULL == dest) {
                    length = 0;
                    return NULL;
                }

                std::shared_ptr<Byte> src = this->_buffer;
                if (NULL == src) {
                    length = 0;
                    return NULL;
                }

                memcpy(dest.get(), src.get(), length);
                return dest;
            }
        
        private:        
            std::shared_ptr<Byte>               NewBuffer(int length) noexcept {
                if (length < 1) {
                    return NULL;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                return ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length);
            }
            bool                                EnsureCapacity(int value) noexcept {
                if (value < 0) {
                    return false;
                }

                int& capacity = this->_capacity;
                if (value > capacity) {
                    int num = value;
                    if (num < 256) {
                        num = 256;
                    }
                    
                    int ndw = capacity * 2;
                    if (num < ndw) {
                        num = ndw;
                    }
                    
                    if ((UInt32)(ndw) > 2147483591u) {
                        if (value > 2147483591) {
                            return false;
                        }

                        num = 2147483591;
                    }
                    return this->SetCapacity(num);
                }
                return true;
            }

        private:
            bool                                _expandable : 1;
            bool                                _disposed   : 7;
            int                                 _position   = 0;
            int                                 _length     = 0;
            int                                 _capacity   = 0;
            std::shared_ptr<Byte>               _buffer;
        };
    }
}