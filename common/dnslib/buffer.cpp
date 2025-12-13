/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

/**
 * DNS Buffer
 *
 * Message compression used by getDomainName and putDomainName:
 *
 * In order to reduce the size of messages, the domain system utilizes a
 * compression scheme which eliminates the repetition of domain names in a
 * message.  In this scheme, an entire domain name or a list of labels at
 * the end of a domain name is replaced with a pointer to a prior occurance
 * of the same name.
 *
 * The pointer takes the form of a two octet sequence:
 *
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     | 1  1|                OFFSET                   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The first two bits are ones.  This allows a pointer to be distinguished
 * from a label, since the label must begin with two zero bits because
 * labels are restricted to 63 octets or less.  (The 10 and 01 combinations
 * are reserved for future use.)  The OFFSET field specifies an offset from
 * the start of the message (i.e., the first octet of the ID field in the
 * domain header).  A zero offset specifies the first byte of the ID field,
 * etc.
 *
 * The compression scheme allows a domain name in a message to be
 * represented as either:
 *
 *    - a sequence of labels ending in a zero octet
 *
 *    - a pointer
 *
 *    - a sequence of labels ending with a pointer
 *
 * Pointers can only be used for occurances of a domain name where the
 * format is not class specific.  If this were not the case, a name server
 * or resolver would be required to know the format of all RRs it handled.
 * As yet, there are no such cases, but they may occur in future RDATA
 * formats.
 *
 * If a domain name is contained in a part of the message subject to a
 * length field (such as the RDATA section of an RR), and compression is
 * used, the length of the compressed name is used in the length
 * calculation, rather than the length of the expanded name.
 *
 * Programs are free to avoid using pointers in messages they generate,
 * although this will reduce datagram capacity, and may cause truncation.
 * However all programs are required to understand arriving messages that
 * contain pointers.
 *
 * For example, a datagram might need to use the domain names F.ISI.ARPA,
 * FOO.F.ISI.ARPA, ARPA, and the root.  Ignoring the other fields of the
 * message, these domain names might be represented as:
 *
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     20 |           1           |           F           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     22 |           3           |           I           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     24 |           S           |           I           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     26 |           4           |           A           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     28 |           R           |           P           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     30 |           A           |           0           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     40 |           3           |           F           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     42 |           O           |           O           |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     44 | 1  1|                20                       |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     64 | 1  1|                26                       |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     92 |           0           |                       |
 *        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The domain name for F.ISI.ARPA is shown at offset 20.  The domain name
 * FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
 * concatenate a label for FOO to the previously defined F.ISI.ARPA.  The
 * domain name ARPA is defined at offset 64 using a pointer to the ARPA
 * component of the name F.ISI.ARPA at 20; note that this pointer relies on
 * ARPA being the last label in the string at 20.  The root domain name is
 * defined by a single octet of zeros at 92; the root domain name has no
 * labels.
 */

#include <iostream>
#include <algorithm>
#include <cstring>

#include "buffer.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4267)
#endif

using namespace dns;

uint8_t Buffer::readUint8() {
    auto p = movePtr(bufPtr + 1);
    return p ? *p : 0;
}

void Buffer::writeUint8(uint8_t value) {
    auto p = movePtr(bufPtr + 1);
    if (!p) return;
    *p = value & 0xFF;
}

uint16_t Buffer::readUint16() {
    auto p = movePtr(bufPtr + 2);
    return p ? (((uint16_t) p[0]) << 8) + p[1] : 0;
}

void Buffer::writeUint16(uint16_t value) {
    auto p = movePtr(bufPtr + 2);
    if (!p) return;
    p[0] = (value & 0xFF00) >> 8;
    p[1] = value & 0xFF;
}

uint32_t Buffer::readUint32() {
    auto p = movePtr(bufPtr + 4);
    if (!p) return 0;

    uint32_t value = 0;
    value += ((uint32_t) p[0]) << 24;
    value += ((uint32_t) p[1]) << 16;
    value += ((uint32_t) p[2]) << 8;
    value += (uint32_t) p[3];
    return value;
}

void Buffer::writeUint32(uint32_t value) {
    auto p = movePtr(bufPtr + 4);
    if (!p) return;
    p[0] = (value & 0xFF000000) >> 24;
    p[1] = (value & 0x00FF0000) >> 16;
    p[2] = (value & 0x0000FF00) >> 8;
    p[3] = value & 0x000000FF;
}

void Buffer::seek(size_t pos) {
    movePtr(bufBase + pos);
}

uint8_t *Buffer::readBytes(size_t count) {
    return movePtr(bufPtr + count);
}

bool Buffer::readBytes(size_t count, std::vector<uint8_t> &out) {
    auto p = readBytes(count);
    if (!p) return false;
    out.assign(p, p+count);
    return true;
}

bool Buffer::readBytes(size_t count, uint8_t *out) {
    auto p = readBytes(count);
    if (!p) return false;
    memcpy(out, p, count);
    return true;
}

void Buffer::writeBytes(const uint8_t *data, size_t count) {
    if (count == 0) {
        return; // maybe something wrong
    }
    auto p = movePtr(bufPtr + count);
    if (p) {
        memcpy(p, data, count);
    }
}

std::string Buffer::readCharString() {
    std::string result;
    auto len = readUint8();    // read first octet (byte) to know length of string
    if (len > 0) {
        auto p = readBytes(len);
        if (!p) return result;
        result.append((char *)p, len); // read label
    }
    return result;
}

void Buffer::writeCharString(const std::string &value) {
    writeUint8(value.length());
    writeBytes((const uint8_t *) value.c_str(), value.length());
}

std::string Buffer::readDomainName(bool compressionAllowed) { // NOLINT(misc-no-recursion)
    std::string domain;

    // store current position to avoid of endless recursion for "bad link addresses"
    if (std::find(domainLinkPos.begin(), domainLinkPos.end(), pos()) != domainLinkPos.end()) {
        markBroken(BufferResult::LabelCompressionLoop); // labels compression contains endless loop of links
        return domain;
    }

    domainLinkPos.push_back(pos());

    // read domain name from buffer
    while (true) {
        // get first byte to decide if we are reading link, empty string or string of nonzero length
        auto ctrlCode = readUint8();
        // if we are on the end of the string
        if (ctrlCode == 0) {
            break;
        }

        // if we are on the link
        if (ctrlCode >> 6 == 3) {
            // check if compression is allowed
            if (!compressionAllowed) {
                markBroken(BufferResult::LabelCompressionDisallowed); // compression link found where links are not allowed
                return domain;
            }

            // read second byte and get link address
            auto ctrlCode2 = readUint8();
            auto linkAddr = ((ctrlCode & 63) << 8) + ctrlCode2;
            // change buffer position
            auto saveBuffPos = pos();
            seek(linkAddr);
            std::string linkDomain = readDomainName();
            seek(saveBuffPos);

            if (!domain.empty()) {
                domain.push_back('.');
            }
            domain.append(linkDomain);
            // link always terminates the domain name (no zero at the end in this case)
            break;
        }

        // otherwise, we are reading a label
        {
            if (ctrlCode > kMaxLabelLen) {
                markBroken(BufferResult::LabelTooLong); // too long domain label (max length is 63 characters)
                return domain;
            }

            if (!domain.empty()) {
                domain.push_back('.');
            }
            auto p = readBytes(ctrlCode);
            if (!p) return domain;
            domain.append((char *)p, ctrlCode); // read label
        }
    }

    domainLinkPos.pop_back();

    if (domain.length() > kMaxDomainLen) {
        markBroken(BufferResult::DomainTooLong); // domain name is too long
        return domain;
    }

    return domain;
}

void Buffer::writeDomainName(const std::string &value, bool compressionAllowed) {
    if (value.length() > kMaxDomainLen) {
        markBroken(BufferResult::DomainTooLong); // Domain name too long to be stored in dns message
        return;
    }

    // write empty domain
    if (value.empty() || value == ".") {
        writeUint8(0);
        return;
    }

    std::vector<uint8_t> domain;
    std::vector<size_t> domainLabelIndexes;

    {
        // convert value to <domain> without links as defined in RFC: abcd.efg.hi -> |0x4|a|b|c|d|0x3|e|f|g|0x2|h|i|0x0|
        domain.push_back(0); // first byte is label length (will be set later)
        size_t labelLenPos = 0; // position of label length byte
        for (size_t i = 0; i <= value.length(); i++) {
            if (i == value.length() || value[i] == '.') {
                auto labelLen = (uint8_t) (domain.size() - labelLenPos - 1);
                if (labelLen > kMaxLabelLen) {
                    markBroken(BufferResult::LabelTooLong); // Encoding failed because of too long domain label (max length is 63 characters)
                    return;
                }
                domain[labelLenPos] = labelLen;
                domainLabelIndexes.push_back(labelLenPos);
                domain.push_back(0); // start a new label (with length byte)
                labelLenPos = domain.size() - 1;
                if (i == value.length() - 1) {
                    break; // do not add duplicate zero byte at the end
                }
            } else {
                domain.push_back(value[i]);
            }
        }
    }

    if (!compressionAllowed) {
        // compression is disabled, domain is written as it is
        writeBytes(domain.data(), domain.size());
        return;
    }

    // look for domain name parts in buffer and look for fragments for compression
    // loop over all domain labels
    for (size_t i = 0; i < domainLabelIndexes.size(); i++) {
        uint8_t *subDomain = domain.data() + domainLabelIndexes[i]; // pointer to subdomain (including initial byte for first label length)
        size_t subDomainLen = domain.size() - domainLabelIndexes[i];

        // find the subDomain in the domainPositions
        for (auto &domainPos : domainPositions) {
            if (domainPos.first.size() == subDomainLen && memcmp(domainPos.first.data(), subDomain, subDomainLen) == 0) {
                // link starts with value 0b11000000_00000000
                writeUint16(0xc000 + domainPos.second);
                return;
            }
        }
        // current label didn't appear before, write current label and remember it in domainPositions
        auto subLabelLen = (uint8_t) subDomain[0];
        domainPositions.emplace_back(std::vector<uint8_t>(subDomain, subDomain + subDomainLen), pos());
        writeBytes((uint8_t *) subDomain, subLabelLen + 1);
    }

    writeUint8(0); // write terminating zero if no compression tip was found and all labels are written to buffer
}

uint8_t *Buffer::movePtr(uint8_t *newPtr) {
    if (bufResult != BufferResult::NoError) return nullptr;

    size_t p = newPtr - bufBase;
    if (p > bufLen) {
        markBroken(BufferResult::BufferOverflow);
        return nullptr;
    }

    auto oldPtr = bufPtr;
    bufPtr = newPtr;
    return oldPtr;
}

#ifdef _WIN32
#pragma warning(pop)
#endif