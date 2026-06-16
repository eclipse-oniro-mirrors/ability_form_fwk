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

#include "formtimerrefreshimpltwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#include "data_center/form_data_mgr.h"
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

void CreateRefreshData(FuzzedDataProvider *fdp, RefreshData &refreshData)
{
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
}

void TestRefreshFormRequest(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestDealRefresh(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    bool isCountTimerRefresh = fdp->ConsumeBool();
    bool isTimerRefresh = fdp->ConsumeBool();
    FormTimerRefreshImpl::GetInstance().DetectControlPoint(refreshData, isCountTimerRefresh, isTimerRefresh);
}

void TestBuildTimerWant(FuzzedDataProvider *fdp)
{
    FormTimer formTimer;
    formTimer.formId = fdp->ConsumeIntegral<int64_t>();
    formTimer.userId = fdp->ConsumeIntegral<int32_t>();
    formTimer.isCountTimer = fdp->ConsumeBool();
    formTimer.isUpdateAt = fdp->ConsumeBool();
    formTimer.refreshType = static_cast<RefreshType>(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REFRESH_TYPE));

    Want want;
    FormTimerRefreshImpl::GetInstance().BuildTimerWant(formTimer, want);
}

void TestDetectControlPointAllBranches(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    for (int i = 0; i < 4; i++) {
        bool isCountTimerRefresh = (i & 1) != 0;
        bool isTimerRefresh = (i & 2) != 0;
        FormTimerRefreshImpl::GetInstance().DetectControlPoint(refreshData, isCountTimerRefresh, isTimerRefresh);
    }
}

void TestBuildTimerWantAllBranches(FuzzedDataProvider *fdp)
{
    for (int i = 0; i < 4; i++) {
        FormTimer formTimer;
        formTimer.formId = fdp->ConsumeIntegral<int64_t>();
        formTimer.userId = fdp->ConsumeIntegral<int32_t>();
        formTimer.isCountTimer = (i & 1) != 0;
        formTimer.isUpdateAt = (i & 2) != 0;
        formTimer.refreshType = static_cast<RefreshType>(fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REFRESH_TYPE));

        Want want;
        FormTimerRefreshImpl::GetInstance().BuildTimerWant(formTimer, want);
    }

    for (int i = 0; i < 5; i++) {
        FormTimer formTimer;
        formTimer.formId = fdp->ConsumeIntegral<int64_t>();
        formTimer.userId = fdp->ConsumeIntegral<int32_t>();
        formTimer.isCountTimer = fdp->ConsumeBool();
        formTimer.isUpdateAt = fdp->ConsumeBool();
        formTimer.refreshType = static_cast<RefreshType>(i);

        Want want;
        FormTimerRefreshImpl::GetInstance().BuildTimerWant(formTimer, want);
    }
}

void TestAllRefreshTypes(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    for (int i = 0; i < 5; i++) {
        refreshData.formTimer.refreshType = static_cast<RefreshType>(i);
        FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
    }
}

void TestEdgeCases(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.formId = 0;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formId = -1;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formId = INT64_MAX;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formId = INT64_MIN;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestTimerCombinations(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    for (int i = 0; i < 4; i++) {
        refreshData.formTimer.isCountTimer = (i & 1) != 0;
        refreshData.formTimer.isUpdateAt = (i & 2) != 0;
        FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
    }
}

void TestSystemAppFlags(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.record.isSystemApp = true;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.record.isSystemApp = false;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestVisibilityFlags(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.record.isVisible = true;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.record.isVisible = false;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestUserIdVariations(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.formTimer.userId = 0;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formTimer.userId = 100;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formTimer.userId = -1;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.formTimer.userId = INT32_MAX;
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestWantParameters(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.want.SetParam(Constants::KEY_IS_TIMER, true);
    refreshData.want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::KEY_IS_TIMER, false);
    refreshData.want.SetParam(Constants::KEY_TIMER_REFRESH, false);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::KEY_IS_TIMER, true);
    refreshData.want.SetParam(Constants::KEY_TIMER_REFRESH, false);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::KEY_IS_TIMER, false);
    refreshData.want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

void TestRefreshTypeParameters(FuzzedDataProvider *fdp)
{
    RefreshData refreshData;
    CreateRefreshData(fdp, refreshData);

    refreshData.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, REFRESHTYPE_DEFAULT);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, REFRESHTYPE_INTERVAL);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, REFRESHTYPE_UPDATETIMES);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);

    refreshData.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, REFRESHTYPE_UPDATENEXTTIME);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(refreshData);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();

    switch (testType % 12) {
        case 0:
            TestRefreshFormRequest(fdp);
            break;
        case 1:
            TestDealRefresh(fdp);
            break;
        case 2:
            TestBuildTimerWant(fdp);
            break;
        case 3:
            TestDetectControlPointAllBranches(fdp);
            break;
        case 4:
            TestBuildTimerWantAllBranches(fdp);
            break;
        case 5:
            TestAllRefreshTypes(fdp);
            break;
        case 6:
            TestEdgeCases(fdp);
            break;
        case 7:
            TestTimerCombinations(fdp);
            break;
        case 8:
            TestSystemAppFlags(fdp);
            break;
        case 9:
            TestVisibilityFlags(fdp);
            break;
        case 10:
            TestUserIdVariations(fdp);
            break;
        case 11:
            TestWantParameters(fdp);
            break;
        default:
            TestRefreshTypeParameters(fdp);
            break;
    }

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
