/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>

#ifdef _WIN32
#include <Winsock2.h>
#else

#include <netinet/in.h>

#endif

#include "message.h"

using namespace dns;

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4267)
#endif

static void decodeResourceRecords(Buffer &buffer, size_t count, std::vector<ResourceRecord> &list) {
    list.resize(count);
    for (auto &rr : list) {
        rr.decode(buffer);
    }
}

BufferResult Message::decode(const uint8_t *buf, size_t size) {
    // we do not check (size > MAX_MSG_LEN) at the moment

    Buffer buff((uint8_t *) buf, size);

    // 2. read header
    mId = buff.readUint16();

    uint16_t fields = buff.readUint16();
    mQr = (fields >> 15) & 1;
    mOpCode = (fields >> 11) & 15;
    mAA = (fields >> 10) & 1;
    mTC = (fields >> 9) & 1;
    mRD = (fields >> 8) & 1;
    mRA = (fields >> 7) & 1;
    mRCode = fields & 15;

    size_t qdCount = buff.readUint16();
    size_t anCount = buff.readUint16();
    size_t nsCount = buff.readUint16();
    size_t arCount = buff.readUint16();

    // 3. read Question Sections
    for (size_t i = 0; i < qdCount; i++) {
        std::string qName = buff.readDomainName();
        auto qType = (RecordType) buff.readUint16();
        auto qClass = (RecordClass) buff.readUint16();

        auto qs = QuestionSection(qName, qType, qClass);
        questions.emplace_back(std::move(qs));
    }

    // 4. read response records
    decodeResourceRecords(buff, anCount, answers);
    decodeResourceRecords(buff, nsCount, authorities);
    decodeResourceRecords(buff, arCount, additions);

    // 5. check that buffer is consumed
    auto result = buff.result();
    if (result != BufferResult::NoError) {
        return result;
    }
    if (buff.pos() != buff.size()) {
        return BufferResult::InvalidData;
    }
    return BufferResult::NoError;
}

BufferResult Message::encode(uint8_t *buf, size_t bufSize, size_t &encodedSize) {
    encodedSize = 0;
    Buffer buff(buf, bufSize);

    // encode header
    buff.writeUint16(mId);

    uint16_t fields = ((mQr & 1) << 15);
    fields |= ((mOpCode & 15) << 11);
    fields |= ((mAA & 1) << 10);
    fields |= ((mTC & 1) << 9);
    fields |= ((mRD & 1) << 8);
    fields |= ((mRA & 1) << 7);
    fields |= ((mRCode & 15));
    buff.writeUint16(fields);

    buff.writeUint16(questions.size());
    buff.writeUint16(answers.size());
    buff.writeUint16(authorities.size());
    buff.writeUint16(additions.size());

    for (auto &rr : questions) {
        rr.encode(buff);
    }
    for (auto &rr : answers) {
        rr.encode(buff);
    }
    for (auto &rr : authorities) {
        rr.encode(buff);
    }
    for (auto &rr : additions) {
        rr.encode(buff);
    }
    encodedSize = buff.pos();
    return buff.result();
}

std::string Message::toDebugString() {
    std::ostringstream text;
    text << "DNS Message " << (mQr ? "response" : "request") << ": id=" << mId << ", op=" << mOpCode << ", QD#=" << questions.size() << ", AN#=" << answers.size() << ",  NS#=" << authorities.size() << ", AR#=" << additions.size() << std::endl;
    for (auto &rr : questions) {
        text << "  Question: " << rr.toDebugString() << std::endl;
    }
    for (auto &rr : answers) {
        text << "  Answer: " << rr.toDebugString() << std::endl;
    }
    for (auto &rr : authorities) {
        text << "  Authority:" << rr.toDebugString() << std::endl;
    }
    for (auto &rr : additions) {
        text << "  Addition: " << rr.toDebugString() << std::endl;
    }
    return text.str();
}

#ifdef _WIN32
#pragma warning(pop)
#endif