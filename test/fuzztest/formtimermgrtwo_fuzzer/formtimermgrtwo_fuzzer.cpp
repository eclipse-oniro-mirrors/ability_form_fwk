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

#define private public
#define protected public
#include "common/timer_mgr/form_timer_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormTimerMgr formTimerMgr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data));

    // Cover AddFormTimerForMultiUpdate (not in original fuzzer)
    std::vector<std::vector<int>> updateAtTimes;
    for (size_t i = 0; i < 3 && i + U32_AT_SIZE * 2 < size; i++) {
        std::vector<int> timePair;
        timePair.push_back(static_cast<int>(GetU32Data(data + i * 8)));
        timePair.push_back(static_cast<int>(GetU32Data(data + i * 8 + 4)));
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
    int64_t nextTime = static_cast<int64_t>(GetU32Data(data));
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
    long nowTime = static_cast<long>(GetU32Data(data));
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

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
