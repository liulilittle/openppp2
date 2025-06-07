/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#ifndef _DNS_DNS_H
#define	_DNS_DNS_H

#include <cstdint>

namespace dns {

// maximal length of domain label name
const size_t kMaxMsgLen = 512;
const size_t kMaxLabelLen = 63;
const size_t kMaxDomainLen = 255;

// some names (NOERROR/IN) are polluated by Windows.h, so here use "k" prefix (as google code style)

// RCode types, use uint16_t to match the type of Message::mRCode
enum class ResponseCode : uint16_t {
    kNOERROR = 0,
    kFORMERR,
    kSERVFAIL,
    kNXDOMAIN,
    kNOTIMP,
    kREFUSED,
    // 6-15 reserved for future use
};

// Record CLASS
enum class RecordClass : uint16_t {
    kNone = 0,
    kIN, // the Internet
    kCS, // the CSNET class (Obsolete)
    kCH, // the CHAOS class
    kHS, // Hesiod
};

// Record TYPE (aka RData types)
enum class RecordType : uint16_t {
    kNone = 0,

    kA = 1, // IPv4 address
    kNS = 2, // authoritative name server

    kMD = 3, // mail destination (Obsolete - use MX)
    kMF = 4, // mail forwarder (Obsolete - use MX)

    kCNAME = 5, // canonical name for an alias
    SOA = 6, // marks the start of a zone of authority

    kMB = 7, // mailbox domain name (Obsolete)
    kMG = 8, // mail group member (Obsolete)
    kMR = 9, // mail rename domain name (Obsolete)
    kNUL = 10, // null record (Obsolete)
    kWKS = 11, // well known service description (Obsolete)

    kPTR = 12, // domain name pointer
    kHINFO = 13, // host information

    kMINFO = 14, // mailbox or mail list information (Obsolete)

    kMX = 15, // mail exchange
    kTXT = 16, // text strings
    kAAAA = 28, // IPv6 address
    kSRV = 33, // service record specifies
    kNAPTR = 35, // naming authority pointer

    kOPT = 41, // pseudo-record to support EDNS
    kANY = 255, // wildcard *
};

std::string toString(RecordClass c);
std::string toString(RecordType t);

} // namespace
#endif	/* _DNS_DNS_H */
