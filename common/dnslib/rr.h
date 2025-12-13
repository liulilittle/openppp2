/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#ifndef _DNS_RR_H
#define _DNS_RR_H

#include <string>
#include <vector>
#include <memory>
#include <cstring>

#ifdef _WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "dns.h"
#include "buffer.h"

namespace dns {

class ResourceRecord;

/** Abstract class that act as base for all Resource Record RData types */
class RData {
protected:
    virtual std::ostringstream ossDebugString();
public:
    ResourceRecord *record = nullptr;

    virtual ~RData() = default;
    virtual RecordType getType() = 0;
    virtual void decode(Buffer &buffer, size_t dataLen) = 0;
    virtual void encode(Buffer &buffer) = 0;
    virtual std::string toDebugString() = 0;
};

/**
* RData with name of type dns domain
*/
class RDataWithName : public RData {
public:
    // <domain-name> as defined in DNS RFC (sequence of labels)
    std::string mName;

    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* CName Representation
*/
class RDataCNAME : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kCNAME; };
};

/**
* HINFO Record Representation
*/
class RDataHINFO : public RData {
public:
    std::string mCpu; // CPU type
    std::string mOs; // Operating system type

    RecordType getType() override { return RecordType::kHINFO; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* MB RData Representation
*
* A name specifies <domain-name> of host which has the specified mailbox.
*/
class RDataMB : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kMB; };
};

/**
* MD RData Representation
*
* A <domain-name> specifies a host which has a mail agent for the domain
* which should be able to deliver mail for the domain.
*/
class RDataMD : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kMD; };
};

/**
* MF RData Representation
*
* A <domain-name> which specifies a host which has a mail agent for the domain
* which will accept mail for forwarding to the domain.
*/
class RDataMF : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kMF; };
};

/**
* MG RData Representation
*
* A <domain-name> which specifies a mailbox which is a member of the mail group
* specified by the domain name.
*/
class RDataMG : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kMG; };
};

/**
* MINFO Record Representation
*/
class RDataMINFO : public RData {
public:
    // A <domain-name> which specifies a mailbox which is
    // responsible for the mailing list or mailbox.
    std::string mRMailBx;
    // A <domain-name> which specifies a mailbox which is to
    // receive error messages related to the mailing list or
    // mailbox specified by the owner of the MINFO RR.
    std::string mMailBx;

    RecordType getType() override { return RecordType::kMINFO; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* MR RData Representation
*
* A <domain-name> which specifies a mailbox which is the
* proper rename of the specified mailbox.
*/
class RDataMR : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kMR; };
};

/**
* MX Record Representation
*/
class RDataMX : public RData {
public:
    // A 16 bit integer which specifies the preference given to
    // this RR among others at the same owner.  Lower values are preferred.
    uint16_t mPreference = 0;
    // A <domain-name> which specifies a host willing to act
    // as a mail exchange for the owner name
    std::string mExchange;

    RecordType getType() override { return RecordType::kMX; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/** Generic RData field which stores raw RData bytes.
*
* This class is used for cases when RData type is not known or
* class for appropriate type is not implemented. */
class RDataUnknown : public RData {
public:
    std::vector<uint8_t> mData;

    RecordType getType() override;
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* NS RData Representation
*
* A <domain-name> which specifies a host which should be
* authoritative for the specified class and domain.
*/
class RDataNS : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kNS; };
};

/**
* PTR RData Representation
*
* A <domain-name> which points to some location in the
* domain name space.
*/
class RDataPTR : public RDataWithName {
public:
    RecordType getType() override { return RecordType::kPTR; };
};

/**
* SOA Record Representation
*/
class RDataSOA : public RData {
public:
    // The <domain-name> of the name server that was the
    // original or primary source of data for this zone.
    std::string mMName;
    // A <domain-name> which specifies the mailbox of the
    // person responsible for this zone.
    std::string mRName;
    // The unsigned 32 bit version number of the original copy
    // of the zone.  Zone transfers preserve this value.  This
    // value wraps and should be compared using sequence space
    // arithmetic.
    uint32_t mSerial = 0;
    // A 32 bit time interval before the zone should be refreshed.
    uint32_t mRefresh = 0;
    // A 32 bit time interval that should elapse before a
    // failed refresh should be retried.
    uint32_t mRetry = 0;
    // A 32 bit time value that specifies the upper limit on
    // the time interval that can elapse before the zone is no
    // longer authoritative.
    uint32_t mExpire = 0;
    // The unsigned 32 bit minimum TTL field that should be
    // exported with any RR from this zone.
    uint32_t mMinimum = 0;

    RecordType getType() override { return RecordType::SOA; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* TXT Record Representation
*
* TXT RRs are used to hold descriptive text.  The semantics of the text
* depends on the domain where it is found.
*/
class RDataTXT : public RData {
public:
    // One or more <character-string>s.
    std::vector<std::string> mTexts;

    RecordType getType() override { return RecordType::kTXT; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* A Record Representation (IPv4 address)
*/
class RDataA : public RData {
public:
    void setAddress(const uint8_t *addr) { memcpy(mAddr, addr, 4); }
    void setAddress(const std::string &addr) { inet_pton(AF_INET, addr.c_str(), &mAddr); }
    uint8_t *getAddress() { return mAddr; };

    RecordType getType() override { return RecordType::kA; }
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;

private:
    uint8_t mAddr[4] = {};
};

/**
* WKS Record Representation
*/
class RDataWKS : public RData {
public:
    // An 8 bit IP protocol number
    uint8_t mProtocol = 0;
    // A variable length bit map.  The bit map must be a multiple of 8 bits long.
    std::vector<uint8_t> mBitmap;

    void setAddress(const uint8_t *addr) { memcpy(mAddr, addr, 4); }
    uint8_t *getAddress() { return mAddr; };

    RecordType getType() override { return RecordType::kWKS; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
private:
    uint8_t mAddr[4] = {};
};

/**
* AAAA Record Representation (IPv6 address)
*/
class RDataAAAA : public RData {
public:
    void setAddress(const uint8_t *addr) { memcpy(mAddr, addr, 16); }
    uint8_t *getAddress() { return mAddr; }

    RecordType getType() override { return RecordType::kAAAA; }
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
private:
    uint8_t mAddr[16] = {}; // 128 bit IPv6 address.
};


// http://www.ietf.org/rfc/rfc2915.txt - NAPTR
class RDataNAPTR : public RData {
public:
    uint16_t mOrder = 0;
    uint16_t mPreference = 0;
    std::string mFlags;
    std::string mServices;
    std::string mRegExp;
    std::string mReplacement;

    RecordType getType() override { return RecordType::kNAPTR; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/**
* SRV Record Representation
*/
class RDataSRV : public RData {
public:
    uint16_t mPriority = 0;
    uint16_t mWeight = 0;
    uint16_t mPort = 0;
    std::string mTarget;

    RecordType getType() override { return RecordType::kSRV; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

class RDataOPT : public RData {
public:
    std::vector<uint8_t> mData;

    RecordType getType() override { return RecordType::kOPT; };
    void decode(Buffer &buffer, size_t dataLen) override;
    void encode(Buffer &buffer) override;
    std::string toDebugString() override;
};

/** Represents DNS Resource Record
*
* Each resource record has the following format (exceptions: OPT, etc)
*
*                                     1  1  1  1  1  1
*       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*     |                                               |
*     /                                               /
*     /                      NAME                     /
*     |                                               |
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*     |                      TYPE                     |
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*     |                     CLASS                     |
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*     |                      TTL                      |
*     |                                               |
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*     |                   RDLENGTH                    |
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
*     /                     RDATA                     /
*     /                                               /
*     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*
* where:
*
* NAME            a domain name to which this resource record pertains.
*
* TYPE            two octets containing one of the RR type codes.  This
*                 field specifies the meaning of the data in the RDATA
*                 field.
*
* CLASS           two octets which specify the class of the data in the
*                 RDATA field.
*
* TTL             a 32 bit unsigned integer that specifies the time
*                 interval (in seconds) that the resource record may be
*                 cached before it should be discarded.  Zero values are
*                 interpreted to mean that the RR can only be used for the
*                 transaction in progress, and should not be cached.
*
* RDLENGTH        an unsigned 16 bit integer that specifies the length in
*                 octets of the RDATA field.
*
* RDATA           a variable length string of octets that describes the
*                 resource.  The format of this information varies
*                 according to the TYPE and CLASS of the resource record.
*                 For example, the if the TYPE is A and the CLASS is IN,
*                 the RDATA field is a 4 octet ARPA Internet address.
*/
class ResourceRecord {
public:
    std::string mName; // Domain name to which this resource record pertains
    RecordType mType = RecordType::kNone;
    RecordClass mClass = RecordClass::kNone;
    uint32_t mTtl = 0;

    template<typename T>
    void setRData(std::shared_ptr<T> rData) {
        rData->record = this;
        mRData = std::static_pointer_cast<RData>(rData);
    }

    template<typename T>
    std::shared_ptr<T> getRData() {
        return std::static_pointer_cast<T>(mRData);
    }

    void decode(Buffer &buffer);
    void encode(Buffer &buffer);
    std::string toDebugString();
private:
    std::shared_ptr<RData> mRData;
};

} // namespace
#endif    /* _DNS_RR_H */
