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

#include "formdebugadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr/form_debug_adapter.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormDebugAdapter::GetInstance();

    // Fuzz DumpStorageFormInfos
    std::string storageFormInfos;
    adapter.DumpStorageFormInfos(storageFormInfos);

    // Fuzz DumpTemporaryFormInfos
    std::string temporaryFormInfos;
    adapter.DumpTemporaryFormInfos(temporaryFormInfos);

    // Fuzz DumpStaticBundleFormInfos
    std::string staticBundleFormInfos;
    adapter.DumpStaticBundleFormInfos(staticBundleFormInfos);

    // Fuzz DumpFormInfoByBundleName
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string formInfosByBundle;
    adapter.DumpFormInfoByBundleName(bundleName, formInfosByBundle);

    // Fuzz DumpFormInfoByFormId
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string formInfoByFormId;
    adapter.DumpFormInfoByFormId(formId, formInfoByFormId);

    // Fuzz DumpFormTimerByFormId
    int64_t timerFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string isTimingService;
    adapter.DumpFormTimerByFormId(timerFormId, isTimingService);

    // Fuzz DumpHasFormVisible
    std::string bundleInfo = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string visibleFormInfos;
    adapter.DumpHasFormVisible(bundleInfo, visibleFormInfos);

    // Fuzz DumpFormRunningFormInfos
    std::string runningFormInfosResult;
    adapter.DumpFormRunningFormInfos(runningFormInfosResult);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
