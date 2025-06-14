/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#ifndef _DNS_MESSAGE_H
#define	_DNS_MESSAGE_H

#include <string>
#include <vector>

#include "dns.h"
#include "rr.h"
#include "qs.h"
#include "buffer.h"

namespace dns {

/**
 * Class represents the DNS Message.
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message.  The top level format of message is divided
 * into 5 sections (some of which are empty in certain cases) shown below:
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
 *
 * The header section is always present.  The header includes fields that
 * specify which of the remaining sections are present, and also specify
 * whether the message is a query or a response, a standard query or some
 * other opcode, etc.
 *
 * Header section format
 *
 * The header contains the following fields:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * ID              A 16 bit identifier assigned by the program that generates any kind of query.  This identifier is copied
 *                 the corresponding reply and can be used by the requester to match up replies to outstanding queries.
 *
 * QR              A one bit field that specifies whether this message is a query (0), or a response (1).
 *
 * OPCODE          A four bit field that specifies kind of query in this message.  This value is set by the originator of a query
 *                 and copied into the response.  The values are:
 *
 *                 0               a standard query (QUERY)
 *                 1               an inverse query (IQUERY)
 *                 2               a server status request (STATUS)
 *                 3-15            reserved for future use
 *
 * AA              Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an
 *                 authority for the domain name in question section.
 *
 *                 Note that the contents of the answer section may have multiple owner names because of aliases.  The AA bit
 *                 corresponds to the name which matches the query name, or the first owner name in the answer section.
 *
 * TC              TrunCation - specifies that this message was truncated due to length greater than that permitted on the
 *                 transmission channel.
 *
 * RD              Recursion Desired - this bit may be set in a query and is copied into the response.  If RD is set, it directs
 *                 the name server to pursue the query recursively. Recursive query support is optional.
 *
 * RA              Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is
 *                 available in the name server.
 *
 * Z               Reserved for future use.  Must be zero in all queries and responses.
 *
 * RCODE           Response code - this 4 bit field is set as part of
 *                 responses.  The values have the following
 *                 interpretation:
 *
 *                 0               No error condition
 *                 1               Format error - The name server was unable to interpret the query.
 *                 2               Server failure - The name server was unable to process this query due to a problem with
 *                                 the name server.
 *                 3               Name Error - Meaningful only for responses from an authoritative name
 *                                 server, this code signifies that the domain name referenced in the query does not exist.
 *                 4               Not Implemented - The name server does not support the requested kind of query.
 *                 5               Refused - The name server refuses to perform the specified operation for
 *                                 policy reasons.  For example, a name server may not wish to provide the
 *                                 information to the particular requester, or a name server may not wish to perform
 *                                 a particular operation (e.g., zone transfer) for particular data.
 *                 6-15            Reserved for future use.
 *
 * QDCOUNT         an unsigned 16 bit integer specifying the number of entries in the question section.
 * ANCOUNT         an unsigned 16 bit integer specifying the number of resource records in the answer section.
 * NSCOUNT         an unsigned 16 bit integer specifying the number of name server resource records in the authority records section.
 * ARCOUNT         an unsigned 16 bit integer specifying the number of resource records in the additional records section.
 */

class Message {
public:
    uint16_t mId = 0;

    // the following fields are stored in one 16bit - by bits
    uint16_t mQr = 0; // query (0) or response (1)
    uint16_t mOpCode = 0; // kind of query
    uint16_t mAA = 0; // Authoritative Answer
    uint16_t mTC = 0; // Truncation Cation
    uint16_t mRD = 0; // Recursion Desired
    uint16_t mRA = 0; // Recursion Available
    uint16_t mRCode = 0; // Response code

    std::vector<QuestionSection> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additions;

    BufferResult decode(const uint8_t* buf, size_t size);
    BufferResult encode(uint8_t* buf, size_t bufSize, size_t &encodedSize);

    // char *buf is for debug purpose only
    BufferResult decode(const char* buf, size_t size) { return decode((uint8_t *)buf, size); }
    BufferResult encode(char* buf, size_t bufSize, size_t &encodedSize)  { return encode((uint8_t *)buf, bufSize, encodedSize); }

    std::string toDebugString();
};
} // namespace
#endif	/* _DNS_MESSAGE_H */
