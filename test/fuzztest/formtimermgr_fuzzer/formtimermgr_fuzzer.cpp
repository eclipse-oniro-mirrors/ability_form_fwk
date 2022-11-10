/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formtimermgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_timer_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
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
    FormTimer task;
    formTimerMgr.AddFormTimer(task);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    long updateDuration = static_cast<long>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formTimerMgr.AddFormTimer(formId, updateDuration, userId);
    long updateAtHour = static_cast<long>(GetU32Data(data));
    long updateAtMin = static_cast<long>(GetU32Data(data));
    formTimerMgr.AddFormTimer(formId, updateAtHour, updateAtMin, userId);
    formTimerMgr.RemoveFormTimer(formId);
    UpdateType type = UpdateType::TYPE_INTERVAL_CHANGE;
    FormTimerCfg timerCfg;
    formTimerMgr.UpdateFormTimer(formId, type, timerCfg);
    formTimerMgr.UpdateIntervalValue(formId, timerCfg);
    formTimerMgr.UpdateAtTimerValue(formId, timerCfg);
    formTimerMgr.IntervalToAtTimer(formId, timerCfg);
    formTimerMgr.AtTimerToIntervalTimer(formId, timerCfg);
    formTimerMgr.IsLimiterEnableRefresh(formId);
    formTimerMgr.IncreaseRefreshCount(formId);
    long nextGapTime = static_cast<long>(GetU32Data(data));
    formTimerMgr.SetNextRefreshTime(formId, nextGapTime, userId);
    bool flag = *data % ENABLE;
    formTimerMgr.SetEnableFlag(formId, flag);
    formTimerMgr.GetRefreshCount(formId);
    formTimerMgr.MarkRemind(formId);
    formTimerMgr.AddUpdateAtTimer(task);
    formTimerMgr.AddIntervalTimer(task);
    UpdateAtItem atItem;
    formTimerMgr.AddUpdateAtItem(atItem);
    formTimerMgr.HandleSystemTimeChanged();
    formTimerMgr.HandleResetLimiter();
    long updateTime = static_cast<long>(GetU32Data(data));
    formTimerMgr.OnUpdateAtTrigger(updateTime);
    int64_t updateTimes = static_cast<int64_t>(GetU32Data(data));
    formTimerMgr.OnDynamicTimeTrigger(updateTimes);
    std::vector<FormTimer> remindTasks;
    remindTasks.emplace_back(task);
    formTimerMgr.GetRemindTasks(remindTasks);
    formTimerMgr.SetIntervalEnableFlag(formId, flag);
    formTimerMgr.GetIntervalTimer(formId, task);
    formTimerMgr.GetUpdateAtTimer(formId, atItem);
    DynamicRefreshItem dynamicItem;
    formTimerMgr.GetDynamicItem(formId, dynamicItem);
    int32_t timeSpeed = static_cast<int32_t>(GetU32Data(data));
    formTimerMgr.SetTimeSpeed(timeSpeed);
    formTimerMgr.DeleteIntervalTimer(formId);
    formTimerMgr.DeleteUpdateAtTimer(formId);
    formTimerMgr.DeleteDynamicItem(formId);
    formTimerMgr.OnIntervalTimeOut();
    formTimerMgr.UpdateAtTimerAlarm();
    long updateAtTime = static_cast<long>(GetU32Data(data));
    formTimerMgr.GetUpdateAtWantAgent(updateAtTime, userId);
    formTimerMgr.ClearUpdateAtTimerResource();
    return formTimerMgr.UpdateLimiterAlarm();
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

