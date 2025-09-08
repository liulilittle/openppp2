/*
 * Copyright (c) 2022 Xiaoguang Wang (mailto:wxiaoguang@gmail.com)
 * Copyright (c) 2014 Michal Nezerka (https://github.com/mnezerka/, mailto:michal.nezerka@gmail.com)
 * Licensed under the NCSA Open Source License (https://opensource.org/licenses/NCSA). All rights reserved.
 */

#include <iostream>
#include <sstream>

#include "buffer.h"
#include "qs.h"

using namespace dns;

std::string QuestionSection::toDebugString() {
    auto oss = std::ostringstream();
    oss << toString(mType) << " " << mName << " " << toString(mClass);
    return oss.str();
}

void QuestionSection::encode(Buffer &buffer) {
    buffer.writeDomainName(mName);
    buffer.writeUint16((uint16_t)mType);
    buffer.writeUint16((uint16_t)mClass);
}
