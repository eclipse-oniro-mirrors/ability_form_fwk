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
constexpr int32_t MAX_NUM = 1000;
constexpr int32_t MIN_RATIO_NUM = 10;
constexpr int32_t MIN_NUM = 0;

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
    FormAbnormalReporter::GetInstance().AddRecord(formId, formAbnormalInfo);
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    FormAbnormalReporter::GetInstance().CheckForms();
    FormAbnormalReporter::GetInstance().ReportAbnormalForms();
    FormAbnormalReporter::GetInstance().ClearRecords();
    
    FormAbnormalReportParams params;
    params.bundleNames.emplace_back("testBundle");
    params.moduleNames.emplace_back("testModule");
    params.abilityNames.emplace_back("testAbility");
    params.formNames.emplace_back("testForm");
    params.formDimensions.emplace_back(1);
    params.formLocations.emplace_back(0);
    params.appVersions.emplace_back("1.0");
    params.nonTransparencyRateList.emplace_back(50);
    ClearEventParams(params);
    
    return params.bundleNames.empty() && params.moduleNames.empty() &&
           params.abilityNames.empty() && params.formNames.empty() &&
           params.formDimensions.empty() && params.formLocations.empty() &&
           params.appVersions.empty() && params.nonTransparencyRateList.empty();
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
