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

#include "formabnormalreporter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "feature/form_check/form_abnormal_info.h"
#include "feature/form_check/form_abnormal_reporter.h"
#include "form_event_report_define.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 1000;
constexpr int32_t MIN_RATIO_NUM = 10;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;
constexpr int32_t MAX_RATIO = 100;

inline void ClearEventParams(FormAbnormalReportParams &params)
{
    params.bundleNames.clear();
    params.moduleNames.clear();
    params.abilityNames.clear();
    params.formNames.clear();
    params.formDimensions.clear();
    params.formLocations.clear();
    params.appVersions.clear();
    params.nonTransparencyRateList.clear();
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int64_t formId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    int64_t ratio = fdp->ConsumeIntegralInRange(MIN_NUM, MIN_RATIO_NUM);
    
    FormAbnormalReporter::GetInstance().AddRecord(formId, ratio);
    
    FormAbnormalInfo formAbnormalInfo {};
    formAbnormalInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formAbnormalInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formAbnormalInfo.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formAbnormalInfo.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formAbnormalInfo.formDimension = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formAbnormalInfo.formLocation = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formAbnormalInfo.appVersion = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formAbnormalInfo.nonTransparentRatio = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_RATIO);
    FormAbnormalReporter::GetInstance().AddRecord(formId, formAbnormalInfo);
    
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    
    bool shouldCheck = fdp->ConsumeBool();
    if (shouldCheck) {
        FormAbnormalReporter::GetInstance().CheckForms();
    }
    
    bool shouldReport = fdp->ConsumeBool();
    if (shouldReport) {
        FormAbnormalReporter::GetInstance().ReportAbnormalForms();
    }
    
    bool shouldClear = fdp->ConsumeBool();
    if (shouldClear) {
        FormAbnormalReporter::GetInstance().ClearRecords();
    }
    
    FormAbnormalReportParams params;
    int32_t numItems = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < numItems; i++) {
        params.bundleNames.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        params.moduleNames.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        params.abilityNames.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        params.formNames.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        params.formDimensions.emplace_back(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM));
        params.formLocations.emplace_back(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM));
        params.appVersions.emplace_back(fdp->ConsumeRandomLengthString(MAX_LENGTH));
        params.nonTransparencyRateList.emplace_back(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_RATIO));
    }
    ClearEventParams(params);
    
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
