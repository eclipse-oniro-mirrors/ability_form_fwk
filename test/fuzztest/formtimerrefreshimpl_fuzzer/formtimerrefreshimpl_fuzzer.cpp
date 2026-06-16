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

#include "formtimerrefreshimpl_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t REFRESHTYPE_DEFAULT = 0;
constexpr int32_t REFRESHTYPE_INTERVAL = 1;
constexpr int32_t REFRESHTYPE_UPDATETIMES = 2;
constexpr int32_t REFRESHTYPE_UPDATENEXTTIME = 3;
constexpr int32_t MAX_REFRESH_TYPE = 4;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormTimerRefreshImpl formTimerRefresh;

    RefreshData refreshData;
    refreshData.formId = fdp->ConsumeIntegral<int64_t>();
    refreshData.callingUid = fdp->ConsumeIntegral<int32_t>();
    refreshData.nextTime = fdp->ConsumeIntegral<int64_t>();

    FormRecord record;
    record.formId = refreshData.formId;
    record.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.isSystemApp = fdp->ConsumeBool();
    record.isVisible = fdp->ConsumeBool();
    record.isCountTimerRefresh = fdp->ConsumeBool();
    record.isTimerRefresh = fdp->ConsumeBool();
    record.userId = fdp->ConsumeIntegral<int32_t>();
    record.uid = fdp->ConsumeIntegral<int32_t>();
    refreshData.record = record;

    FormTimer formTimer;
    formTimer.formId = refreshData.formId;
    formTimer.userId = fdp->ConsumeIntegral<int32_t>();
    formTimer.isCountTimer = fdp->ConsumeBool();
    formTimer.isUpdateAt = fdp->ConsumeBool();
    formTimer.refreshType = static_cast<RefreshType>(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REFRESH_TYPE));
    refreshData.formTimer = formTimer;

    Want want;
    want.SetParam(Constants::KEY_IS_TIMER, fdp->ConsumeBool());
    want.SetParam(Constants::KEY_TIMER_REFRESH, fdp->ConsumeBool());

    int32_t refreshType = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REFRESH_TYPE);
    want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, refreshType);

    refreshData.want = want;

    FormProviderData providerData;
    refreshData.providerData = providerData;

    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    bool isCountTimerRefresh = fdp->ConsumeBool();
    bool isTimerRefresh = fdp->ConsumeBool();
    FormTimerRefreshImpl::GetInstance().DetectControlPoint(refreshData, isCountTimerRefresh, isTimerRefresh);

    Want timerWant;
    FormTimerRefreshImpl::GetInstance().BuildTimerWant(formTimer, timerWant);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
