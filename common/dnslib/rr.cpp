/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>

#include "buffer.h"
#include "rr.h"

namespace dns {

std::ostringstream RData::ossDebugString() {
    std::ostringstream oss;
    // common debug format:  TYPE DOMAIN CLASS TTL more...
    if (record) {
        oss << toString(getType()) << " " << (record->mName.empty() ? "." : record->mName) << " " << toString(record->mClass) << " " << record->mTtl;
    } else {
        oss << toString(getType()) << " . None 0";
    }
    return oss;
}

/////////// RDataWithName ///////////

void RDataWithName::decode(Buffer &buffer, size_t /*dataLen*/) {
    mName = buffer.readDomainName();
}

void RDataWithName::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
}

std::string RDataWithName::toDebugString() {
    auto oss = ossDebugString();
    oss << " name=" << mName;
    return oss.str();
}


/////////// RDataHINFO /////////////////

void RDataHINFO::decode(Buffer &buffer, size_t /*dataLen*/) {
    mCpu = buffer.readCharString();
    mOs = buffer.readCharString();
}

void RDataHINFO::encode(Buffer &buffer) {
    buffer.writeCharString(mCpu);
    buffer.writeCharString(mOs);
}

std::string RDataHINFO::toDebugString() {
    auto oss = ossDebugString();
    oss << " cpu=" << mCpu << " os=" << mOs;
    return oss.str();
}


/////////// RDataMINFO /////////////////

void RDataMINFO::decode(Buffer &buffer, size_t /*dataLen*/) {
    mRMailBx = buffer.readDomainName();
    mMailBx = buffer.readDomainName();
}

void RDataMINFO::encode(Buffer &buffer) {
    buffer.writeDomainName(mRMailBx);
    buffer.writeDomainName(mMailBx);
}

std::string RDataMINFO::toDebugString() {
    auto oss = ossDebugString();
    oss << " rmailbx=" << mRMailBx << " mailbx=" << mMailBx;
    return oss.str();
}


/////////// RDataMX /////////////////
void RDataMX::decode(Buffer &buffer, size_t /*dataLen*/) {
    mPreference = buffer.readUint16();
    mExchange = buffer.readDomainName();
}

void RDataMX::encode(Buffer &buffer) {
    buffer.writeUint16(mPreference);
    buffer.writeDomainName(mExchange);
}

std::string RDataMX::toDebugString() {
    auto oss = ossDebugString();
    oss << " preference=" << mPreference << " exchange=" << mExchange;
    return oss.str();
}

/////////// RDataUnknown /////////////////
RecordType RDataUnknown::getType() {
    return record->mType;
}

void RDataUnknown::decode(Buffer &buffer, size_t dataLen) {
    buffer.readBytes(dataLen, mData);
}

void RDataUnknown::encode(Buffer &buffer) {
    buffer.writeBytes(mData.data(), mData.size());
}

std::string RDataUnknown::toDebugString() {
    auto oss = ossDebugString();
    oss << " len=" << mData.size();
    return oss.str();
}

/////////// RDataSOA /////////////////

void RDataSOA::decode(Buffer &buffer, size_t /*dataLen*/) {
    mMName = buffer.readDomainName();
    mRName = buffer.readDomainName();
    mSerial = buffer.readUint32();
    mRefresh = buffer.readUint32();
    mRetry = buffer.readUint32();
    mExpire = buffer.readUint32();
    mMinimum = buffer.readUint32();
}

void RDataSOA::encode(Buffer &buffer) {
    buffer.writeDomainName(mMName);
    buffer.writeDomainName(mRName);
    buffer.writeUint32(mSerial);
    buffer.writeUint32(mRefresh);
    buffer.writeUint32(mRetry);
    buffer.writeUint32(mExpire);
    buffer.writeUint32(mMinimum);
}

std::string RDataSOA::toDebugString() {
    auto oss = ossDebugString();
    oss << " mname=" << mMName
        << " rname=" << mRName
        << " serial=" << mSerial
        << " refresh=" << mRefresh
        << " retry=" << mRetry
        << " expire=" << mExpire
        << " minimum=" << mMinimum;
    return oss.str();
}


/////////// RDataTXT /////////////////

void RDataTXT::decode(Buffer &buffer, size_t dataLen) {
    mTexts.clear();
    size_t posStart = buffer.pos();
    while (!buffer.isBroken() && buffer.pos() - posStart < dataLen) {
        mTexts.push_back(buffer.readCharString());
    }
}

void RDataTXT::encode(Buffer &buffer) {
    for (auto &txt : mTexts) {
        buffer.writeCharString(txt);
    }
}

std::string quoteCharString(const std::string &s) {
    std::string result;
    result.push_back('"');
    char buf4[4];
    for (auto c : s) {
        if (c < ' ' || c > '~') {
            snprintf(buf4, sizeof(buf4), "%03o", c);
            result.push_back('\\');
            result += buf4;
        } else if (c == '\\' || c == '"') {
            result.push_back('\\');
            result.push_back(c);
        } else {
            result.push_back(c);
        }
    }
    result.push_back('"');
    return result;
}

std::string RDataTXT::toDebugString() {
    auto oss = ossDebugString();
    for (auto &txt : mTexts) {
        oss << " " << quoteCharString(txt);
    }
    return oss.str();
}

/////////// RDataA /////////////////

void RDataA::decode(Buffer &buffer, size_t /*dataLen*/) {
    buffer.readBytes(4, mAddr);
}

void RDataA::encode(Buffer &buffer) {
    buffer.writeBytes(mAddr, 4);
}

std::string RDataA::toDebugString() {
    char ipAddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (in_addr *)mAddr, ipAddr, INET_ADDRSTRLEN);

    auto oss = ossDebugString();
    oss << " addr=" << ipAddr;
    return oss.str();
}

/////////// RDataWKS /////////////////

void RDataWKS::decode(Buffer &buffer, size_t dataLen) {
    // get ip address
    buffer.readBytes(4, mAddr);

    // get protocol
    mProtocol = buffer.readUint8();

    // get bitmap
    auto bitmapSize = dataLen - 5;
    buffer.readBytes(bitmapSize, mBitmap);
}

void RDataWKS::encode(Buffer &buffer) {
    buffer.writeBytes(mAddr, 4);
    buffer.writeUint8(mProtocol);
    if (!mBitmap.empty()) {
        buffer.writeBytes(mBitmap.data(), mBitmap.size());
    }
}

std::string RDataWKS::toDebugString() {
    char ipAddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, (in_addr *)mAddr, ipAddr, INET_ADDRSTRLEN);

    auto oss = ossDebugString();
    oss << " addr=" << ipAddr << " protocol=" << (uint32_t) mProtocol << " bitmap-size=" << mBitmap.size();
    return oss.str();
}


/////////// RDataAAAA /////////////////

void RDataAAAA::decode(Buffer &buffer, size_t /*dataLen*/) {
    buffer.readBytes(16, mAddr);
}

void RDataAAAA::encode(Buffer &buffer) {
    buffer.writeBytes(mAddr, 16);
}

std::string RDataAAAA::toDebugString() {
    char ipAddr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, (in_addr *)mAddr, ipAddr, INET6_ADDRSTRLEN);

    auto oss = ossDebugString();
    oss << " addr=" << ipAddr;
    return oss.str();
}


/////////// RDataNAPTR /////////////////

void RDataNAPTR::decode(Buffer &buffer, size_t /*dataLen*/) {
    mOrder = buffer.readUint16();
    mPreference = buffer.readUint16();
    mFlags = buffer.readCharString();
    mServices = buffer.readCharString();
    mRegExp = buffer.readCharString();
    mReplacement = buffer.readDomainName(false);
}

void RDataNAPTR::encode(Buffer &buffer) {
    buffer.writeUint16(mOrder);
    buffer.writeUint16(mPreference);
    buffer.writeCharString(mFlags);
    buffer.writeCharString(mServices);
    buffer.writeCharString(mRegExp);
    buffer.writeDomainName(mReplacement, false);
}

std::string RDataNAPTR::toDebugString() {
    auto oss = ossDebugString();
    oss << " order=" << mOrder << " preference=" << mPreference << " flags=" << mFlags << " services=" << mServices << " regexp=" << mRegExp << " replacement=" << mReplacement;
    return oss.str();
}

/////////// RDataSRV /////////////////
void RDataSRV::decode(Buffer &buffer, size_t /*dataLen*/) {
    mPriority = buffer.readUint16();
    mWeight = buffer.readUint16();
    mPort = buffer.readUint16();
    mTarget = buffer.readDomainName();
}

void RDataSRV::encode(Buffer &buffer) {
    buffer.writeUint16(mPriority);
    buffer.writeUint16(mWeight);
    buffer.writeUint16(mPort);
    buffer.writeDomainName(mTarget);
}

std::string RDataSRV::toDebugString() {
    auto oss = ossDebugString();
    oss << " priority=" << mPriority << " weight=" << mWeight << " port=" << mPort << " target=" << mTarget;
    return oss.str();
}

/*
RDataOPT
+------------+--------------+------------------------------+
| Field Name | Field Type   | Description                  |
+------------+--------------+------------------------------+
| NAME       | domain name  | MUST be 0 (root domain)      |
| TYPE       | u_int16_t    | OPT (41)                     |
| CLASS      | u_int16_t    | requestor's UDP payload size |
| TTL        | u_int32_t    | extended RCODE and flags     |
| RDLEN      | u_int16_t    | length of all RDATA          |
| RDATA      | octet stream | {attribute,value} pairs      |
+------------+--------------+------------------------------+
OPT TTL
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
0: |         EXTENDED-RCODE        |            VERSION            |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
2: | DO|                           Z                               |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
void RDataOPT::decode(Buffer &buffer, size_t dataLen) {
    buffer.readBytes(dataLen, mData);
}

void RDataOPT::encode(Buffer &buffer) {
    buffer.writeBytes(mData.data(), mData.size());
}

std::string RDataOPT::toDebugString() {
    auto oss = std::ostringstream();
    oss << "OPT payload_size=" << (uint16_t)record->mClass << " ext=" << (uint32_t) record->mTtl << " len=" << mData.size();
    return oss.str();
}

/////////// ResourceRecord ////////////

void ResourceRecord::decode(Buffer &buffer) {
    mName = buffer.readDomainName();
    mType = (RecordType)buffer.readUint16();

    // some pseudo-record type (like OPT) will use Class/Ttl as other meanings
    mClass = (RecordClass) buffer.readUint16();
    mTtl = buffer.readUint32();

    auto dataLen = buffer.readUint16();
    switch (mType) {
        case RecordType::kCNAME:
            mRData = std::make_shared<RDataCNAME>();
            break;
        case RecordType::kHINFO:
            mRData = std::make_shared<RDataHINFO>();
            break;
        case RecordType::kMB:
            mRData = std::make_shared<RDataMB>();
            break;
        case RecordType::kMD:
            mRData = std::make_shared<RDataMD>();
            break;
        case RecordType::kMF:
            mRData = std::make_shared<RDataMF>();
            break;
        case RecordType::kMG:
            mRData = std::make_shared<RDataMG>();
            break;
        case RecordType::kMINFO:
            mRData = std::make_shared<RDataMINFO>();
            break;
        case RecordType::kMR:
            mRData = std::make_shared<RDataMR>();
            break;
        case RecordType::kMX:
            mRData = std::make_shared<RDataMX>();
            break;
        case RecordType::kNS:
            mRData = std::make_shared<RDataNS>();
            break;
        case RecordType::kPTR:
            mRData = std::make_shared<RDataPTR>();
            break;
        case RecordType::SOA:
            mRData = std::make_shared<RDataSOA>();
            break;
        case RecordType::kTXT:
            mRData = std::make_shared<RDataTXT>();
            break;
        case RecordType::kA:
            mRData = std::make_shared<RDataA>();
            break;
        case RecordType::kWKS:
            mRData = std::make_shared<RDataWKS>();
            break;
        case RecordType::kAAAA:
            mRData = std::make_shared<RDataAAAA>();
            break;
        case RecordType::kNAPTR:
            mRData = std::make_shared<RDataNAPTR>();
            break;
        case RecordType::kSRV:
            mRData = std::make_shared<RDataSRV>();
            break;
        case RecordType::kOPT:
            mRData = std::make_shared<RDataOPT>();
            break;
        default:
            mRData = std::make_shared<RDataUnknown>();
    }

    mRData->record = this;

    // RData can refer up to the offset after the dataLen in buffer
    if (dataLen) {
        auto expectedEndPos = buffer.pos() + dataLen;
        mRData->decode(buffer, dataLen);
        if (buffer.pos() != expectedEndPos) {
            buffer.markBroken(BufferResult::InvalidData);
        }
    }
}

void ResourceRecord::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
    buffer.writeUint16((uint16_t)mRData->getType());
    // TODO: some pseudo-record type (like OPT) will use Class/Ttl as other meanings
    buffer.writeUint16((uint16_t)mClass);
    buffer.writeUint32(mTtl);
    // save position of buffer for later use (write length of RData part)
    size_t bufferPosRDataLength = buffer.pos();
    buffer.writeUint16(0); // this value could be later overwritten
    // encode RData if present
    if (mRData) {
        mRData->encode(buffer);
        // sub 2 because two bytes for RData length are not part of RData block
        auto dataLen = buffer.pos() - bufferPosRDataLength - 2;
        size_t bufferLastPos = buffer.pos();
        buffer.seek(bufferPosRDataLength);
        buffer.writeUint16((uint16_t)dataLen); // overwrite 0 with actual size of RData
        buffer.seek(bufferLastPos);
    }
}

std::string ResourceRecord::toDebugString() {
    return mRData->toDebugString();
}

std::string toString(RecordClass c) {
    switch (c) {
        case RecordClass::kNone:
            return "None";
        case RecordClass::kIN:
            return "IN";
        case RecordClass::kCS:
            return "CS";
        case RecordClass::kCH:
            return "CH";
        case RecordClass::kHS:
            return "HS";
        default:
            return "CLASS" + std::to_string((int)c);
    }
}

std::string toString(RecordType t) {
    switch (t) {
        case RecordType::kNone:
            return "None";
        case RecordType::kCNAME:
            return "CNAME";
        case RecordType::kHINFO:
            return "HINFO";
        case RecordType::kMB:
            return "MB";
        case RecordType::kMD:
            return "MD";
        case RecordType::kMF:
            return "MF";
        case RecordType::kMG:
            return "MG";
        case RecordType::kMINFO:
            return "MINFO";
        case RecordType::kMR:
            return "MR";
        case RecordType::kMX:
            return "MX";
        case RecordType::kNS:
            return "NS";
        case RecordType::kPTR:
            return "PTR";
        case RecordType::SOA:
            return "SOA";
        case RecordType::kTXT:
            return "TXT";
        case RecordType::kA:
            return "A";
        case RecordType::kWKS:
            return "WKS";
        case RecordType::kAAAA:
            return "AAAA";
        case RecordType::kNAPTR:
            return "NAPTR";
        case RecordType::kSRV:
            return "SRV";
        case RecordType::kOPT:
            return "OPT";
        default:
            return "TYPE" + std::to_string((int)t);
    }
}

}
