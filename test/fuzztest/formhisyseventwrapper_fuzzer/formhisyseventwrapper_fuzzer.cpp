/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "formhisyseventwrapper_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define private public
#define protected public
#include "form_hisysevent_wrapper.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MAX_LOOP_COUNT = 10;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormHiSysEventBuilder builder;

    // Test InsertParam with uint32_t value
    std::string keyUint32 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    uint32_t valueUint32 = fdp->ConsumeIntegral<uint32_t>();
    builder.InsertParam(keyUint32, valueUint32);

    // Test InsertParam with uint8_t value
    std::string keyUint8 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    uint8_t valueUint8 = fdp->ConsumeIntegral<uint8_t>();
    builder.InsertParam(keyUint8, valueUint8);

    // Test InsertParam with double value
    std::string keyDouble = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    double valueDouble = fdp->ConsumeFloatingPointInRange<double>(0.0, MAX_NUM);
    builder.InsertParam(keyDouble, valueDouble);

    // Test InsertParam with vector<uint32_t>
    std::string keyVecUint32 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<uint32_t> vecUint32;
    int32_t vecUint32Size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < vecUint32Size; i++) {
        vecUint32.push_back(fdp->ConsumeIntegral<uint32_t>());
    }
    builder.InsertParam(keyVecUint32, vecUint32);

    // Test InsertParam with vector<string>
    std::string keyVecString = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<std::string> vecString;
    int32_t vecStringSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < vecStringSize; i++) {
        vecString.push_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    }
    builder.InsertParam(keyVecString, vecString);

    // Test Write
    std::string domain = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string eventName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    HiSysEventEventType eventType = fdp->ConsumeBool() ? HISYSEVENT_BEHAVIOR : HISYSEVENT_FAULT;
    builder.Write(domain, eventName, eventType);

    // Test Clear
    builder.Clear();

    // Test FormHiSysEventWrapper::WriteEvent
    std::string wrapperDomain = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string wrapperEventName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    HiSysEventEventType wrapperEventType = fdp->ConsumeBool() ? HISYSEVENT_BEHAVIOR : HISYSEVENT_FAULT;
    FormHiSysEventWrapper::WriteEvent(wrapperDomain, wrapperEventName, wrapperEventType);

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
