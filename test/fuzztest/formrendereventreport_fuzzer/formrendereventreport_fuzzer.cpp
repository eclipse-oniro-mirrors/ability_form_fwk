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
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormRenderEventReport::GetNowMillisecond();
    PerformanceEventInfo eventInfo;
    FormRenderEventReport::SendPerformanceEvent(SceneType::CPU_SCENE_ENTRY, eventInfo);
    std::string bundleName = fdp->ConsumeRandomLengthString();
    std::string errorName = fdp->ConsumeRandomLengthString();
    std::string errorMsg = fdp->ConsumeRandomLengthString();
    FormRenderEventReport::SendBlockFaultEvent(bundleName, errorName, errorMsg);
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string uid = fdp->ConsumeRandomLengthString();
    FormRenderEventReport::StartReleaseTimeoutReportTimer(formId, uid);
    FormRenderEventReport::StopReleaseTimeoutReportTimer(formId);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}