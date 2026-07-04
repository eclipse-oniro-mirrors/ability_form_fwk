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

#include "formappupgraderefreshimpl_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_app_upgrade_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;

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
    data.formTimer.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);
    data.callerToken = nullptr;
    return data;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormAppUpgradeRefreshImpl formAppUpgradeRefresh;
    RefreshData data = GenerateFuzzedRefreshData(fdp);

    // Test public method
    formAppUpgradeRefresh.RefreshFormRequest(data);

    // Test protected method DoRefresh (override)
    formAppUpgradeRefresh.DoRefresh(data);

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
