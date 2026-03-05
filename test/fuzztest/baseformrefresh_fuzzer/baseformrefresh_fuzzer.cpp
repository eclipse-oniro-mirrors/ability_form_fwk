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

#include "baseformrefresh_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_refresh/refresh_impl/base_form_refresh.h"
#include "form_refresh/refresh_impl/form_refresh_interface.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = -10000;

/**
 * @brief Generate fuzzed RefreshData
 */
RefreshData GenerateFuzzedRefreshData(FuzzedDataProvider *fdp)
{
    RefreshData data;
    if (fdp == nullptr) {
        return data;
    }
    data.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    data.nextTime = fdp->ConsumeIntegral<int64_t>();
    data.callingUid = fdp->ConsumeIntegral<int32_t>();
    data.record.formId = data.formId;
    data.record.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.isEnableUpdate = fdp->ConsumeBool();
    data.record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    data.formTimer.formId = data.formId;
    data.formTimer.refreshTime = fdp->ConsumeIntegral<int64_t>();
    data.formTimer.userId = fdp->ConsumeIntegral<int32_t>();
    data.callerToken = nullptr;
    return data;
}

/**
 * @brief Generate fuzzed RefreshConfig
 */
RefreshConfig GenerateFuzzedRefreshConfig(FuzzedDataProvider *fdp)
{
    RefreshConfig config;
    if (fdp == nullptr) {
        return config;
    }
    int32_t checkCount = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
    for (int32_t i = 0; i < checkCount; i++) {
        config.checkTypes.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    config.controlCheckFlags = fdp->ConsumeIntegral<uint32_t>();
    config.refreshType = fdp->ConsumeIntegral<int32_t>();
    config.isVisibleToFresh = fdp->ConsumeBool();
    return config;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    RefreshConfig config = GenerateFuzzedRefreshConfig(fdp);
    BaseFormRefresh baseFormRefresh(std::move(config));

    RefreshData data = GenerateFuzzedRefreshData(fdp);

    // Test public method RefreshFormRequest
    baseFormRefresh.RefreshFormRequest(data);

    // Test protected method BuildCheckFactor
    baseFormRefresh.BuildCheckFactor(data);

    // Test protected method DoControlCheck
    baseFormRefresh.DoControlCheck(data);

    // Test protected method DoRefresh
    baseFormRefresh.DoRefresh(data);

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
