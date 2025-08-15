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

#include "formtimermgrannex_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "common_event_support.h"

#define private public
#define protected public
#include "data_center/form_info/form_info_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t LIMIT_MAX = 55;
constexpr int32_t INDEX_MAX = 2;
constexpr char FMS_TIME_SPEED[] = "fms.time_speed";
void FormRefreshLimiterTest(FuzzedDataProvider *fdp)
{
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    int32_t limitCount = fdp->ConsumeIntegralInRange(1, LIMIT_MAX);
    formRefreshLimiter.AddItem(formId);
    for (int32_t i = 0; i <= limitCount; i++) {
        formRefreshLimiter.Increase(formId);
    }
    formRefreshLimiter.IsEnableRefresh(formId);
    formRefreshLimiter.GetRefreshCount(formId);
    formRefreshLimiter.GetRemindList();
    formRefreshLimiter.GetRemindListAndResetLimit();
    formRefreshLimiter.GetRemindList();
    formRefreshLimiter.MarkRemind(formId);
    formRefreshLimiter.DeleteItem(formId);
    formRefreshLimiter.ResetLimit();

}

void FormTimeMgrTest(FuzzedDataProvider *fdp)
{
    FormTimerMgr formTimerMgr;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::vector<UpdateType> types = {UpdateType::TYPE_INTERVAL_CHANGE, UpdateType::TYPE_ATTIME_CHANGE,
        UpdateType::TYPE_INTERVAL_TO_ATTIME, UpdateType::TYPE_ATTIME_TO_INTERVAL,
        UpdateType::TYPE_INTERVAL_ONCE, UpdateType::TYPE_NO_CHANGE};
    UpdateType type = types.at(fdp->ConsumeIntegralInRange<size_t>(0, types.size() - 1));
    FormTimerCfg timerCfg;
    timerCfg.enableUpdate = fdp->ConsumeBool();
    timerCfg.updateDuration = fdp->ConsumeIntegral<int64_t>();
    timerCfg.updateAtHour = fdp->ConsumeIntegral<int>();
    timerCfg.updateAtMin = fdp->ConsumeIntegral<int>();
    int32_t index1 = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    int32_t index2 = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    std::vector<std::vector<int>> updateAtTimes = {};
    std::vector<int> updateAtTimeVector = {};
    for (int32_t i = 0; i < index1; i++) {
        updateAtTimeVector.push_back(fdp->ConsumeIntegral<int>());
    }
    for (int32_t i = 0; i < index2; i++) {
        updateAtTimes.push_back(updateAtTimeVector);
    }
    timerCfg.updateAtTimes = updateAtTimes;
    formTimerMgr.UpdateFormTimer(formId, type, timerCfg);
    formTimerMgr.IsNeedUpdate();
    formTimerMgr.dynamicRefreshTasks_.clear();
    formTimerMgr.dynamicAlarmTimerId_ = fdp->ConsumeIntegral<uint64_t>();
    formTimerMgr.reportDiskUseTimerId_ = fdp->ConsumeIntegral<uint64_t>();
    long updateAtTime = fdp->ConsumeIntegral<long>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    formTimerMgr.currentDynamicWantAgent_ = formTimerMgr.GetUpdateAtWantAgent(updateAtTime, userId);
    formTimerMgr.UpdateDynamicAlarm();
    formTimerMgr.StartDiskUseInfoReportTimer();
    formTimerMgr.ClearDiskInfoReportTimer();
    FormTimerMgr::TimerReceiver timerReceiver;
    EventFwk::CommonEventData eventData;
    Want want;
    std::vector<std::string> actions = {FMS_TIME_SPEED, EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED,
        Constants::ACTION_UPDATEATTIMER, fdp->ConsumeRandomLengthString()};
    std::vector<int32_t> actionTypes = {Constants::TYPE_RESET_LIMIT, Constants::TYPE_STATIC_UPDATE,
        Constants::TYPE_DYNAMIC_UPDATE, fdp->ConsumeIntegral<int32_t>()};
    std::string action = actions.at(fdp->ConsumeIntegralInRange<size_t>(0, actions.size() - 1));
    int32_t actionType = actionTypes.at(fdp->ConsumeIntegralInRange<size_t>(0, actions.size() - 1));
    want.SetAction(action);
    want.SetParam(Constants::KEY_ACTION_TYPE, actionType);
    eventData.SetWant(want);
    timerReceiver.OnReceiveEvent(eventData);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    OHOS::FormRefreshLimiterTest(fdp);
    OHOS::FormTimeMgrTest(fdp);
    FormTimerMgr formTimerMgr;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    int64_t nextTime = fdp->ConsumeIntegral<int64_t>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    std::vector<std::vector<int>> updateAtTimes = {};
    formTimerMgr.AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);
    std::vector<int> updateAtTime1 = {fdp->ConsumeIntegral<int>(), fdp->ConsumeIntegral<int>()};
    std::vector<int> updateAtTime2 = {fdp->ConsumeIntegral<int>(), fdp->ConsumeIntegral<int>()};
    updateAtTimes = {updateAtTime1, updateAtTime2};
    formTimerMgr.AddFormTimerForMultiUpdate(formId, updateAtTimes, userId);
    formTimerMgr.ClearLimiterTimerResource();
    formTimerMgr.GetLimiterWantAgent();
    formTimerMgr.UpdateDynamicAlarm();
    formTimerMgr.GetDynamicWantAgent(nextTime, userId);
    formTimerMgr.ClearDynamicResource();
    long nowTime = fdp->ConsumeIntegral<long>();
    UpdateAtItem updateAtItem;
    formTimerMgr.FindNextAtTimerItem(nowTime, updateAtItem);
    formTimerMgr.ClearIntervalTimer();
    FormTimer timerTask;
    formTimerMgr.ExecTimerTask(timerTask);
    formTimerMgr.Init();
    FormInfoHelper formInfoHelper;
    std::string bundleName = fdp->ConsumeRandomLengthString();
    FormInfo formInfo;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(formInfo);
    formInfoHelper.LoadFormConfigInfoByBundleName(bundleName, formInfos, userId);
    return formTimerMgr.IsActiveUser(userId);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}