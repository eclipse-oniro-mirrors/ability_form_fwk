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

#include "formtimermgrthree_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/timer_mgr/form_timer.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int64_t MAX_NUM = 1000000;
constexpr int64_t MIN_NUM = -100;
constexpr int64_t MIN_PERIOD = 1800000; 
constexpr int64_t MAX_PERIOD = 1209600000;

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormTimerMgr formTimerMgr;
    
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data + 4));
    long updateDuration = static_cast<long>(GetU32Data(data + 8));
    long updateAtHour = static_cast<long>(GetU32Data(data + 12));
    long updateAtMin = static_cast<long>(GetU32Data(data + 16));
    long nextGapTime = static_cast<long>(GetU32Data(data + 20));
    long updateTime = static_cast<long>(GetU32Data(data + 24));
    int64_t updateTime64 = static_cast<int64_t>(GetU32Data(data + 28));
    
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = true;
    
    // 1. UpdateIntervalValue - cover all branches
    timerCfg.updateDuration = static_cast<int64_t>(GetU32Data(data + 32));
    formTimerMgr.UpdateIntervalValue(formId, timerCfg);
    
    timerCfg.updateDuration = 0;
    formTimerMgr.UpdateIntervalValue(formId, timerCfg);
    
    timerCfg.updateDuration = MIN_PERIOD;
    formTimerMgr.UpdateIntervalValue(formId, timerCfg);
    
    timerCfg.updateDuration = MAX_PERIOD;
    formTimerMgr.UpdateIntervalValue(formId, timerCfg);
    
    // 2. UpdateTimerValue - cover all branches
    timerCfg.updateDuration = MIN_PERIOD;
    timerCfg.updateAtHour = static_cast<int>(GetU32Data(data + 36));
    timerCfg.updateAtMin = static_cast<int>(GetU32Data(data + 40));
    
    std::vector<std::vector<int>> updateAtTimes;
    std::vector<int> timePair;
    timePair.push_back(static_cast<int>(GetU32Data(data + 44)));
    timePair.push_back(static_cast<int>(GetU32Data(data + 48)));
    updateAtTimes.push_back(timePair);
    timerCfg.updateAtTimes = updateAtTimes;
    
    UpdateAtItem changedItem;
    formTimerMgr.UpdateTimerValue(formId, timerCfg, changedItem);
    
    // 3. UpdateAtTimerValue - cover all branches
    timerCfg.updateAtHour = 0;
    timerCfg.updateAtMin = 0;
    formTimerMgr.UpdateAtTimerValue(formId, timerCfg);
    
    timerCfg.updateAtHour = 23;
    timerCfg.updateAtMin = 59;
    formTimerMgr.UpdateAtTimerValue(formId, timerCfg);
    
    timerCfg.updateAtHour = static_cast<int>(GetU32Data(data + 52));
    timerCfg.updateAtMin = static_cast<int>(GetU32Data(data + 56));
    formTimerMgr.UpdateAtTimerValue(formId, timerCfg);
    
    // 4. IntervalToAtTimer - cover all branches
    timerCfg.updateAtHour = 0;
    timerCfg.updateAtMin = 0;
    formTimerMgr.IntervalToAtTimer(formId, timerCfg);
    
    timerCfg.updateAtHour = 23;
    timerCfg.updateAtMin = 59;
    formTimerMgr.IntervalToAtTimer(formId, timerCfg);
    
    timerCfg.updateAtHour = static_cast<int>(GetU32Data(data + 60));
    timerCfg.updateAtMin = static_cast<int>(GetU32Data(data + 64));
    formTimerMgr.IntervalToAtTimer(formId, timerCfg);
    
    updateAtTimes.clear();
    timePair.clear();
    timePair.push_back(static_cast<int>(GetU32Data(data + 68)));
    timePair.push_back(static_cast<int>(GetU32Data(data + 72)));
    updateAtTimes.push_back(timePair);
    timerCfg.updateAtTimes = updateAtTimes;
    formTimerMgr.IntervalToAtTimer(formId, timerCfg);
    
    // 5. SetNextRefreshTime - cover all branches
    nextGapTime = 500;
    formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId);
    
    nextGapTime = 200;
    formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId);
    
    // 6. HandleResetLimiter
    formTimerMgr.HandleResetLimiter();
    
    // 7. OnDynamicTimeTrigger
    formTimerMgr.OnDynamicTimeTrigger(updateTime64);
    
    // 8. GetRemindTasks
    std::vector<FormTimer> remindTasks;
    formTimerMgr.GetRemindTasks(remindTasks);
    
    // 9. OnIntervalTimeOut
    formTimerMgr.OnIntervalTimeOut();
    
    // 10. ClearUpdateAtTimerResource
    formTimerMgr.ClearUpdateAtTimerResource();
    
    // 11. UpdateLimiterAlarm
    formTimerMgr.UpdateLimiterAlarm();
    
    // 12. UpdateDynamicAlarm
    formTimerMgr.UpdateDynamicAlarm();
    
    // 13. IsNeedUpdate
    formTimerMgr.IsNeedUpdate();
    
    // 14. UpdateAtTimerAlarmDetail - cover all branches
    FormTimer timerTask;
    timerTask.formId = formId;
    timerTask.userId = userId;
    formTimerMgr.UpdateAtTimerAlarmDetail(timerTask);
    
    timerTask.formId = 0;
    formTimerMgr.UpdateAtTimerAlarmDetail(timerTask);
    
    return true;
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE * 20) {
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
