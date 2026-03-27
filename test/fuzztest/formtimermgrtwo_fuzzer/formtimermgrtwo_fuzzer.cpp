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

#include "formtimermgrtwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/timer_mgr/form_timer_mgr.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormTimerMgr formTimerMgr;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();

    // Cover AddFormTimerForMultiUpdate (not in original fuzzer)
    std::vector<std::vector<int>> updateAtTimes;
    int32_t numTimePairs = fdp->ConsumeIntegralInRange(0, 3);
    for (int32_t i = 0; i < numTimePairs; i++) {
        std::vector<int> timePair;
        timePair.push_back(fdp->ConsumeIntegral<int>());
        timePair.push_back(fdp->ConsumeIntegral<int>());
        updateAtTimes.push_back(timePair);
    }
    formTimerMgr.AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);

    // Cover UpdateDynamicAlarm (not in original fuzzer)
    formTimerMgr.UpdateDynamicAlarm();

    // Cover StartDiskUseInfoReportTimer (not in original fuzzer)
    formTimerMgr.StartDiskUseInfoReportTimer();

    // Cover StartFormCheckTimer (not in original fuzzer)
    formTimerMgr.StartFormCheckTimer();

    // Cover DestroyFormCheckTimer (not in original fuzzer)
    formTimerMgr.DestroyFormCheckTimer();

    // Cover private methods that need fuzzing
    FormTimer task;
    formTimerMgr.ExecTimerTask(task);

#ifdef RES_SCHEDULE_ENABLE
    formTimerMgr.ExecTimerTaskCore(task);
#endif

    // Cover GetLimiterWantAgent (not in original fuzzer)
    formTimerMgr.GetLimiterWantAgent();

    // Cover GetDynamicWantAgent (not in original fuzzer)
    int64_t nextTime = fdp->ConsumeIntegral<int64_t>();
    formTimerMgr.GetDynamicWantAgent(nextTime, userId);

    // Cover IsActiveUser (not in original fuzzer)
    formTimerMgr.IsActiveUser(userId);

    // Cover UpdateTimerValue (private method, not in original fuzzer)
    FormTimerCfg timerCfg;
    UpdateAtItem changedItem;
    formTimerMgr.UpdateTimerValue(formId, timerCfg, changedItem);

    // Cover ClearLimiterTimerResource (private method, not in original fuzzer)
    formTimerMgr.ClearLimiterTimerResource();

    // Cover ClearDynamicResource (private method, not in original fuzzer)
    formTimerMgr.ClearDynamicResource();

    // Cover FindNextAtTimerItem (private method, not in original fuzzer)
    UpdateAtItem updateAtItem;
    long nowTime = fdp->ConsumeIntegral<long>();
    formTimerMgr.FindNextAtTimerItem(nowTime, updateAtItem);

    // Cover CreateLimiterTimer (private method, not in original fuzzer)
    formTimerMgr.CreateLimiterTimer();

    // Cover Init (private method, not in original fuzzer)
    formTimerMgr.Init();

    // Cover EnsureInitIntervalTimer (private method, not in original fuzzer)
    formTimerMgr.EnsureInitIntervalTimer();

    // Cover ClearIntervalTimer (private method, not in original fuzzer)
    formTimerMgr.ClearIntervalTimer();

    // Cover IsNeedUpdate (private method, not in original fuzzer)
    formTimerMgr.IsNeedUpdate();

    // Cover FormPeriodReport (private method, not in original fuzzer)
    formTimerMgr.FormPeriodReport();

    // Cover ClearDiskInfoReportTimer (private method, not in original fuzzer)
    formTimerMgr.ClearDiskInfoReportTimer();

    // Cover InnerClearIntervalTimer (private method, not in original fuzzer)
    formTimerMgr.InnerClearIntervalTimer();

    // Cover InnerClearIntervalReportTimer (private method, not in original fuzzer)
    formTimerMgr.InnerClearIntervalReportTimer();

    // Cover IsDynamicTimerExpired (private method, not in original fuzzer)
    formTimerMgr.IsDynamicTimerExpired(formId);

    // Cover UpdateAtTimerAlarmDetail (private method, not in original fuzzer)
    formTimerMgr.UpdateAtTimerAlarmDetail(task);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
