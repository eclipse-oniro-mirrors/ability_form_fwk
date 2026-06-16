/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "formrendereventreport_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_render_event_report.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;
constexpr int32_t MAX_SCENE_TYPE = 1;
constexpr int32_t MAX_EVENT_NAME = 10;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    PerformanceEventInfo eventInfo;
    eventInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    eventInfo.sceneId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    eventInfo.timeStamp = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    
    SceneType sceneType = static_cast<SceneType>(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_SCENE_TYPE));
    FormRenderEventReport::SendPerformanceEvent(sceneType, eventInfo);
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string errorName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string errorMsg = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormRenderEventReport::SendBlockFaultEvent(bundleName, errorName, errorMsg);
    
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    std::string formBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t errorType = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    int32_t errorCode = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    
    FormEventName eventName = static_cast<FormEventName>(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_EVENT_NAME));
    FormRenderEventReport::SendFormFailedEvent(eventName, formId, formBundleName, formName, errorType, errorCode);
    
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormRenderEventReport::StartReleaseTimeoutReportTimer(formId, uid);
    FormRenderEventReport::StopReleaseTimeoutReportTimer(formId);
    
    std::string bundleName2 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    uint64_t processMemory = fdp->ConsumeIntegralInRange<uint64_t>(MIN_NUM, MAX_NUM);
    uint64_t runtimeMemory = fdp->ConsumeIntegralInRange<uint64_t>(MIN_NUM, MAX_NUM);
    
    std::vector<std::string> formNames;
    int32_t numFormNames = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < numFormNames; i++) {
        formNames.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    }
    
    std::vector<uint32_t> formLocations;
    int32_t numFormLocations = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < numFormLocations; i++) {
        formLocations.emplace_back(fdp->ConsumeIntegralInRange<uint32_t>(MIN_NUM, MAX_NUM));
    }
    
    FormRenderEventReport::SendRuntimeMemoryLeakEvent(bundleName2, processMemory, runtimeMemory, formNames,
        formLocations);
    
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
