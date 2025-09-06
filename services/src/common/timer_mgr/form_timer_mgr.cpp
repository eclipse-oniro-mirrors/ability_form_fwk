/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "common/timer_mgr/form_timer_mgr.h"

#include <cinttypes>

#include "common_event_manager.h"
#include "common_event_support.h"
#include "context/context.h"
#include "ffrt.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_provider/form_provider_mgr.h"
#include "common/timer_mgr/form_timer_option.h"
#include "common/util/form_util.h"
#include "in_process_call_wrapper.h"
#include "os_account_manager_wrapper.h"
#include "time_service_client.h"
#include "time_common.h"
#include "want.h"
#include "form_event_report.h"
#include "data_center/form_record/form_record_report.h"
#include "data_center/form_data_mgr.h"
#include "form_refresh/form_refresh_mgr.h"
#include "feature/memory_mgr/form_render_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int REQUEST_UPDATE_AT_CODE = 1;
constexpr int REQUEST_LIMITER_CODE = 2;
constexpr int REQUEST_DYNAMIC_CODE = 3;
constexpr int SHIFT_BIT_LENGTH = 32;
constexpr int NANO_TO_SECOND =  1000000000;
constexpr char FMS_TIME_SPEED[] = "fms.time_speed";
// Specified custom timer event publisher uid, publisher must be foundation
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int64_t TIMER_UPDATE_INTERVAL = 5 * 60 * 1000;
constexpr int64_t TIMER_UPDATEAT_CREATE_BEHIND_TRIGGER = 10 * 1000;
} // namespace

FormTimerMgr::FormTimerMgr()
{
    Init();
}
FormTimerMgr::~FormTimerMgr()
{
    ClearIntervalTimer();
    if (currentLimiterWantAgent_ != nullptr) {
        ClearLimiterTimerResource();
    }
}
/**
 * @brief Add form timer by timer task.
 * @param task The form timer task.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddFormTimer(const FormTimer &task)
{
    HILOG_INFO("formId:%{public}s userId:%{public}d", std::to_string(task.formId).c_str(), task.userId);
    if (task.isUpdateAt) {
        if (task.hour >= Constants::MIN_TIME && task.hour <= Constants::MAX_HOUR &&
            task.min >= Constants::MIN_TIME && task.min <= Constants::MAX_MINUTE) {
            return AddUpdateAtTimer(task);
        } else {
            HILOG_ERROR("invalid update");
            return false;
        }
    } else {
        if (task.period >= (Constants::MIN_PERIOD / timeSpeed_) && // Min period is 30 minutes
            task.period <= (Constants::MAX_PERIOD / timeSpeed_) && // Max period is 1 week
            task.period % (Constants::MIN_PERIOD / timeSpeed_) == 0) {
            return AddIntervalTimer(task);
        } else {
            HILOG_ERROR("invalid intervalTime");
            return false;
        }
    }
}
/**
 * @brief Add duration form timer.
 * @param formId The Id of the form.
 * @param updateDuration Update duration
 * @param userId User ID.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddFormTimer(int64_t formId, long updateDuration, int32_t userId)
{
    auto duration = updateDuration / timeSpeed_;
    HILOG_INFO("formId:%{public}s duration:%{public}s",
        std::to_string(formId).c_str(), std::to_string(duration).c_str());
    FormTimer timerTask(formId, duration, userId);
    return AddFormTimer(timerTask);
}
/**
 * @brief Add scheduled form timer.
 * @param formId The Id of the form.
 * @param updateAtHour Hour.
 * @param updateAtMin Min.
 * @param userId User ID.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddFormTimer(int64_t formId, long updateAtHour, long updateAtMin, int32_t userId)
{
    HILOG_INFO("formId:%{public}s time:%{public}s-%{public}s",
        std::to_string(formId).c_str(), std::to_string(updateAtHour).c_str(), std::to_string(updateAtMin).c_str());
    FormTimer timerTask(formId, updateAtHour, updateAtMin, userId);
    return AddFormTimer(timerTask);
}

/**
 * @brief Add scheduled form timer.
 * @param formId The Id of the form.
 * @param updateAtTimes multi updatetime.
 * @param userId User ID.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddFormTimerForMultiUpdate(int64_t formId, std::vector<std::vector<int>> updateAtTimes,
    int32_t userId)
{
    if (updateAtTimes.size() == 0) {
        HILOG_ERROR("no multiUpdateAtTimes");
        return false;
    }
    bool result = true;
    for (const auto &time : updateAtTimes) {
        FormTimer timerTask(formId, time[0], time[1], userId);
        timerTask.needUpdateAlarm = false;
        result = AddFormTimer(timerTask);
        if (!result) {
            HILOG_ERROR("set multiUpdateAtTimes failed time[0] : %{public}d ,time[1] : %{public}d ",
                (int)time[0], (int)time[1]);
            return false;
        }
    }

    if (!UpdateLimiterAlarm()) {
        HILOG_ERROR("UpdateLimiterAlarm failed");
        return false;
    }

    if (!UpdateAtTimerAlarm()) {
        HILOG_ERROR("updateAtTimerAlarm failed");
        return false;
    }
    return true;
}


/**
 * @brief Remove form timer by form id.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::RemoveFormTimer(int64_t formId)
{
    HILOG_INFO("remove timer, formId:%{public}" PRId64, formId);

    if (!DeleteIntervalTimer(formId)) {
        if (!DeleteUpdateAtTimer(formId)) {
            HILOG_ERROR("fail DeleteUpdateAtTimer");
            return false;
        }
    }

    if (!DeleteDynamicItem(formId)) {
        HILOG_ERROR("fail DeleteDynamicItem");
        return false;
    }
    refreshLimiter_.DeleteItem(formId);

    return true;
}
/**
 * @brief Update form timer.
 * @param formId The Id of the form.
 * @param type Timer type.
 * @param timerCfg Timer config.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateFormTimer(int64_t formId, const UpdateType &type, const FormTimerCfg &timerCfg)
{
    if (!timerCfg.enableUpdate) {
        HILOG_WARN("enableUpdate is false");
        return false;
    }

    switch (type) {
        case UpdateType::TYPE_INTERVAL_CHANGE: {
            return UpdateIntervalValue(formId, timerCfg);
        }
        case UpdateType::TYPE_ATTIME_CHANGE: {
            return UpdateAtTimerValue(formId, timerCfg);
        }
        case UpdateType::TYPE_INTERVAL_TO_ATTIME: {
            return IntervalToAtTimer(formId, timerCfg);
        }
        case UpdateType::TYPE_ATTIME_TO_INTERVAL: {
            return AtTimerToIntervalTimer(formId, timerCfg);
        }
        default: {
            HILOG_ERROR("invalid UpdateType");
            return false;
        }
    }
}
/**
 * @brief Update Interval timer task value.
 * @param formId The Id of the form.
 * @param timerCfg task value.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateIntervalValue(int64_t formId, const FormTimerCfg &timerCfg)
{
    if (timerCfg.updateDuration < Constants::MIN_PERIOD || timerCfg.updateDuration > Constants::MAX_PERIOD
        || (timerCfg.updateDuration % Constants::MIN_PERIOD) != 0) {
        HILOG_ERROR("invalid param");
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    auto intervalTask = intervalTimerTasks_.find(formId);
    if (intervalTask != intervalTimerTasks_.end()) {
        intervalTask->second.period = timerCfg.updateDuration / timeSpeed_;
        return true;
    } else {
        HILOG_ERROR("intervalTimer not exist");
        return false;
    }
}
/**
 * @brief Update update at timer task value.
 * @param formId The Id of the form.
 * @param timerCfg task value.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateAtTimerValue(int64_t formId, const FormTimerCfg &timerCfg)
{
    if (timerCfg.updateAtHour < Constants::MIN_TIME || timerCfg.updateAtHour > Constants::MAX_HOUR
        || timerCfg.updateAtMin < Constants::MIN_TIME || timerCfg.updateAtMin > Constants::MAX_MINUTE) {
        HILOG_ERROR("invalid time");
        return false;
    }
    UpdateAtItem changedItem;

    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        std::list<UpdateAtItem>::iterator itItem;

        for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end();) {
            if (itItem->refreshTask.formId == formId) {
                changedItem = *itItem;
                itItem = updateAtTimerTasks_.erase(itItem);
            } else {
                itItem++;
            }
        }

        if (changedItem.refreshTask.formId == 0) {
            HILOG_ERROR("the updateAtTimer not exist");
            return false;
        }

        std::vector<std::vector<int>> updateAtTimes = timerCfg.updateAtTimes;
        if (updateAtTimes.size() > 0) {
            bool ret = ERR_OK;
            for (const auto &time: updateAtTimes) {
                HILOG_INFO("time[0] : %{public}d ,time[1] : %{public}d ", (int)time[0], (int)time[1]);
                UpdateAtItem changedItem_ = changedItem;
                changedItem_.refreshTask.hour = time[0];
                changedItem_.refreshTask.min = time[1];
                auto updateAtTime = time[0] * Constants::MIN_PER_HOUR + time[1];
                changedItem_.updateAtTime = updateAtTime;
                AddUpdateAtItem(changedItem_);
            }
        } else {
            HILOG_INFO("updateAtHour : %{public}d ,updateAtMin : %{public}d ",
                (int)timerCfg.updateAtHour, (int)timerCfg.updateAtMin);
            changedItem.refreshTask.hour = timerCfg.updateAtHour;
            changedItem.refreshTask.min = timerCfg.updateAtMin;
            changedItem.updateAtTime = changedItem.refreshTask.hour * Constants::MIN_PER_HOUR
                + changedItem.refreshTask.min;
            AddUpdateAtItem(changedItem);
        }
    }

    if (!UpdateAtTimerAlarm()) {
        HILOG_ERROR("updateAtTimerAlarm failed");
        return false;
    }
    return true;
}
/**
 * @brief Interval timer task to update at timer task.
 * @param formId The Id of the form.
 * @param timerCfg task value.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::IntervalToAtTimer(int64_t formId, const FormTimerCfg &timerCfg)
{
    if (timerCfg.updateAtHour < Constants::MIN_TIME || timerCfg.updateAtHour > Constants::MAX_HOUR
        || timerCfg.updateAtMin < Constants::MIN_TIME || timerCfg.updateAtMin > Constants::MAX_MINUTE) {
        HILOG_ERROR("invalid time");
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    FormTimer timerTask;
    auto intervalTask = intervalTimerTasks_.find(formId);
    if (intervalTask != intervalTimerTasks_.end()) {
        timerTask = intervalTask->second;
        intervalTimerTasks_.erase(intervalTask);

        std::vector<std::vector<int>> updateAtTimes = timerCfg.updateAtTimes;
        if (updateAtTimes.size() == 0) {
            timerTask.isUpdateAt = true;
            timerTask.hour = timerCfg.updateAtHour;
            timerTask.min = timerCfg.updateAtMin;
            if (!AddUpdateAtTimer(timerTask)) {
                HILOG_ERROR("fail AddUpdateAtTimer");
                return false;
            }
            return true;
        }
        for (const auto &time: updateAtTimes) {
            FormTimer timerTask_ = timerTask;
            timerTask_.isUpdateAt = true;
            timerTask_.hour = time[0];
            timerTask_.min = time[1];
            if (!AddUpdateAtTimer(timerTask_)) {
                HILOG_ERROR("fail AddUpdateAtTimer");
                return false;
            }
        }
        return true;
    } else {
        HILOG_ERROR("intervalTimer not exist");
        return false;
    }
}
/**
 * @brief Update at timer task to interval timer task.
 * @param formId The Id of the form.
 * @param timerCfg task value.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AtTimerToIntervalTimer(int64_t formId, const FormTimerCfg &timerCfg)
{
    if (timerCfg.updateDuration < Constants::MIN_PERIOD || timerCfg.updateDuration > Constants::MAX_PERIOD
        || (timerCfg.updateDuration % Constants::MIN_PERIOD) != 0) {
        HILOG_ERROR("invalid time");
        return false;
    }

    UpdateAtItem targetItem;
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        std::list<UpdateAtItem>::iterator itItem;
        for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end();) {
            if (itItem->refreshTask.formId == formId) {
                targetItem = *itItem;
                itItem = updateAtTimerTasks_.erase(itItem);
            } else {
                itItem++;
            }
        }
    }

    if (!UpdateAtTimerAlarm()) {
        HILOG_ERROR("updateAtTimerAlarm failed");
        return false;
    }

    if (targetItem.refreshTask.formId == 0) {
        HILOG_ERROR("the updateAtTimer not exist");
        return false;
    }
    targetItem.refreshTask.isUpdateAt = false;
    targetItem.refreshTask.period = timerCfg.updateDuration;
    targetItem.refreshTask.refreshTime = FormUtil::GetCurrentMillisecond();
    if (!AddIntervalTimer(targetItem.refreshTask)) {
        HILOG_ERROR("fail add interval timer");
        return false;
    }
    return true;
}
/**
 * @brief Is limiter enable refresh.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::IsLimiterEnableRefresh(int64_t formId)
{
    return refreshLimiter_.IsEnableRefresh(formId);
}
/**
 * @brief Increase refresh count.
 * @param formId The Id of the form.
 */
void FormTimerMgr::IncreaseRefreshCount(int64_t formId)
{
    refreshLimiter_.Increase(formId);
}
/**
 * @brief Set next refresh time.
 * @param formId The Id of the form.
 * @param nextGapTime Next gap time(ms).
 * @param userId User ID.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::SetNextRefreshTime(int64_t formId, long nextGapTime, int32_t userId)
{
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return false;
    }

    if (!record.isSystemApp && nextGapTime < Constants::MIN_NEXT_TIME) {
        HILOG_ERROR("invalid nextGapTime:%{public}ld", nextGapTime);
        FormEventReport::SendFormFailedEvent(FormEventName::UPDATE_FORM_FAILED, formId,
            record.bundleName, record.formName, TYPE_TIMER, ERR_APPEXECFWK_FORM_INVALID_PARAM);
        return false;
    }
    int64_t timeInSec = GetBootTimeMs();
    int64_t refreshTime = timeInSec + nextGapTime * Constants::MS_PER_SECOND / timeSpeed_;
    HILOG_INFO("currentTime:%{public}s refreshTime:%{public}s",
        std::to_string(timeInSec).c_str(), std::to_string(refreshTime).c_str());
    bool isExist = false;

    {
        std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
        for (auto &refreshItem : dynamicRefreshTasks_) {
            if ((refreshItem.formId == formId) && (refreshItem.userId == userId)) {
                refreshItem.settedTime = refreshTime;
                isExist = true;
                break;
            }
        }
        if (!isExist) {
            DynamicRefreshItem theItem;
            theItem.formId = formId;
            theItem.settedTime = refreshTime;
            theItem.userId = userId;
            dynamicRefreshTasks_.emplace_back(theItem);
        }
        dynamicRefreshTasks_.sort(CompareDynamicRefreshItem);
    }

    if (!UpdateDynamicAlarm()) {
        HILOG_ERROR("fail UpdateDynamicAlarm");
        return false;
    }
    if (!UpdateLimiterAlarm()) {
        HILOG_ERROR("UpdateLimiterAlarm failed");
        return false;
    }
    refreshLimiter_.AddItem(formId);
    SetEnableFlag(formId, false);

    return true;
}

void FormTimerMgr::SetEnableFlag(int64_t formId, bool flag)
{
    // try interval list
    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    auto iter = intervalTimerTasks_.find(formId);
    if (iter != intervalTimerTasks_.end()) {
        iter->second.isEnable = flag;
        HILOG_INFO("formId:%{public}" PRId64 ", isEnable:%{public}d", formId, flag);
        return;
    }
}

/**
 * @brief Get refresh count.
 * @param formId The Id of the form.
 * @return Returns refresh count.
 */
int FormTimerMgr::GetRefreshCount(int64_t formId) const
{
    return refreshLimiter_.GetRefreshCount(formId);
}
/**
 * @brief Mark remind.
 * @param formId The Id of the form.
 * @return true or false.
 */
void FormTimerMgr::MarkRemind(int64_t formId)
{
    refreshLimiter_.MarkRemind(formId);
}
/**
 * @brief Add update at timer.
 * @param task Update time task.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddUpdateAtTimer(const FormTimer &task)
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        auto updateAtTime = task.hour * Constants::MIN_PER_HOUR + task.min;
        for (const auto &updateAtTimer : updateAtTimerTasks_) {
            if (updateAtTimer.refreshTask.formId == task.formId && updateAtTimer.updateAtTime == updateAtTime) {
                HILOG_WARN("already exist formTimer, formId:%{public}" PRId64 " task",
                    task.formId);
                return true;
            }
        }
        UpdateAtItem atItem;
        atItem.refreshTask = task;
        atItem.updateAtTime = updateAtTime;
        AddUpdateAtItem(atItem);
    }

    if (task.needUpdateAlarm) {
        if (!UpdateLimiterAlarm()) {
            HILOG_ERROR("UpdateLimiterAlarm failed");
            return false;
        }
        FormTimer newTask(task.formId, task.hour, task.min, task.userId);
        if (!UpdateAtTimerAlarmDetail(newTask)) {
            HILOG_ERROR("updateAtTimerAlarm failed");
            return false;
        }
    }

    return refreshLimiter_.AddItem(task.formId);
}
/**
 * @brief Add update interval timer task.
 * @param task Update interval timer task.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::AddIntervalTimer(const FormTimer &task)
{
    HILOG_INFO("call");
    {
        std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
        EnsureInitIntervalTimer();
        if (intervalTimerTasks_.find(task.formId) != intervalTimerTasks_.end()) {
            HILOG_WARN("already exist formTimer, formId:%{public}" PRId64 " task", task.formId);
            return true;
        }
        intervalTimerTasks_.emplace(task.formId, task);
    }
    if (!UpdateLimiterAlarm()) {
        HILOG_ERROR("UpdateLimiterAlarm failed");
        return false;
    }
    return refreshLimiter_.AddItem(task.formId);
}
/**
 * @brief Add update at timer item.
 * @param task Update at timer item.
 */
void FormTimerMgr::AddUpdateAtItem(const UpdateAtItem &atItem)
{
    if (updateAtTimerTasks_.empty()) {
        updateAtTimerTasks_.emplace_back(atItem);
        return;
    }

    UpdateAtItem firstItem = updateAtTimerTasks_.front();
    if (atItem.updateAtTime < firstItem.updateAtTime) {
        updateAtTimerTasks_.emplace_front(atItem);
        return;
    }

    bool isInsert = false;
    std::list<UpdateAtItem>::iterator itItem;
    for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end(); itItem++) {
        if (atItem.updateAtTime < itItem->updateAtTime) {
            updateAtTimerTasks_.insert(itItem, atItem);
            isInsert = true;
            break;
        }
    }

    if (!isInsert) {
        updateAtTimerTasks_.emplace_back(atItem);
    }
}
/**
 * @brief Handle system time changed.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::HandleSystemTimeChanged()
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        if (updateAtTimerTasks_.empty()) {
            UpdateLimiterAlarm();
            return true;
        }
    }
    atTimerWakeUpTime_ = LONG_MAX;
    UpdateAtTimerAlarm();
    HILOG_INFO("end");
    return true;
}
/**
 * @brief Reset form limiter.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::HandleResetLimiter()
{
    HILOG_INFO("start");

    std::vector<FormTimer> remindTasks;
    bool bGetTasks = GetRemindTasks(remindTasks);
    FormRecordReport::GetInstance().AddNewDayReportInfo();
    if (bGetTasks) {
        HILOG_INFO("failed,remind when reset limiter");
        for (auto &task : remindTasks) {
            ExecTimerTask(task);
            int64_t formId = task.formId;
            FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_HF_RECOVER_UPDATE);
            FormRecordReport::GetInstance().IncreaseUpdateTimes(
                formId, HiSysEventPointType::TYPE_PASSIVE_RECOVER_UPDATE);
        }
    }

    HILOG_INFO("end");
    return true;
}
/**
 * @brief Update at time trigger.
 * @param updateTime Update time.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::OnUpdateAtTrigger(long updateTime)
{
    HILOG_INFO("updateTime:%{public}ld", updateTime);
    std::vector<UpdateAtItem> updateList;
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        std::list<UpdateAtItem>::iterator itItem;
        for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end(); itItem++) {
            if (itItem->updateAtTime == updateTime && itItem->refreshTask.isEnable) {
                updateList.emplace_back(*itItem);
            }
        }
    }

    if (!UpdateAtTimerAlarm()) {
        HILOG_ERROR("updateAtTimerAlarm failed");
        return false;
    }

    if (!updateList.empty()) {
        HILOG_INFO("update at timer triggered, trigger time:%{public}ld", updateTime);
        for (auto &item : updateList) {
            item.refreshTask.refreshType = RefreshType::TYPE_UPDATETIMES;
            ExecTimerTask(item.refreshTask);
        }
    }

    HILOG_INFO("end");
    return true;
}
/**
 * @brief Dynamic time trigger.
 * @param updateTime Update time.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::OnDynamicTimeTrigger(int64_t updateTime)
{
    HILOG_INFO("updateTime:%{public}" PRId64, updateTime);
    std::vector<FormTimer> updateList;
    {
        std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
        auto timeInSec = GetBootTimeMs();
        int64_t markedTime = timeInSec + Constants::ABS_REFRESH_MS;
        std::list<DynamicRefreshItem>::iterator itItem;
        for (itItem = dynamicRefreshTasks_.begin(); itItem != dynamicRefreshTasks_.end();) {
            if (itItem->settedTime <= updateTime || itItem->settedTime <= markedTime) {
                if (refreshLimiter_.IsEnableRefresh(itItem->formId)) {
                    FormTimer timerTask(itItem->formId, true, itItem->userId);
                    updateList.emplace_back(timerTask);
                }
                SetIntervalEnableFlag(itItem->formId, true);
                itItem = dynamicRefreshTasks_.erase(itItem);
            } else {
                itItem++;
            }
        }
        dynamicRefreshTasks_.sort(CompareDynamicRefreshItem);
    }

    if (!UpdateDynamicAlarm()) {
        HILOG_ERROR("fail update dynamic alarm");
        return false;
    }

    if (!updateList.empty()) {
        HILOG_INFO("trigger time:%{public}" PRId64, updateTime);
        for (auto &task : updateList) {
            task.refreshType = RefreshType::TYPE_UPDATENEXTTIME;
            ExecTimerTask(task);
        }
    }

    HILOG_INFO("end");
    return true;
}
/**
 * @brief Get remind tasks.
 * @param remindTasks Remind tasks.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::GetRemindTasks(std::vector<FormTimer> &remindTasks)
{
    HILOG_INFO("start");
    std::vector<int64_t> remindList = refreshLimiter_.GetRemindListAndResetLimit();
    for (int64_t id : remindList) {
        FormTimer formTimer(id, false);
        remindTasks.emplace_back(formTimer);
    }

    if (!UpdateLimiterAlarm()) {
        HILOG_ERROR("UpdateLimiterAlarm failed");
        return false;
    }

    if (remindTasks.size() > 0) {
        HILOG_INFO("end");
        return true;
    } else {
        HILOG_INFO("empty remindTasks");
        return false;
    }
}
/**
 * @brief Set enableFlag for interval timer task.
 * @param formId The Id of the form.
 * @param flag Enable flag.
 */
void FormTimerMgr::SetIntervalEnableFlag(int64_t formId, bool flag)
{
    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    // try interval list
    auto refreshTask = intervalTimerTasks_.find(formId);
    if (refreshTask != intervalTimerTasks_.end()) {
        refreshTask->second.isEnable = flag;
        HILOG_INFO("formId:%{public}" PRId64 ", isEnable:%{public}d", formId, flag);
        return;
    }
}
/**
 * @brief Get interval timer task.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::GetIntervalTimer(int64_t formId, FormTimer &formTimer)
{
    HILOG_INFO("start");
    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    auto intervalTask = intervalTimerTasks_.find(formId);
    if (intervalTask == intervalTimerTasks_.end()) {
        HILOG_INFO("interval timer not find");
        return false;
    }
    formTimer = intervalTask->second;
    HILOG_INFO("get interval timer successfully");
    return true;
}
/**
 * @brief Get update at timer.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::GetUpdateAtTimer(int64_t formId, UpdateAtItem &updateAtItem)
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        std::list<UpdateAtItem>::iterator itItem;
        for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end(); itItem++) {
            if (itItem->refreshTask.formId == formId) {
                updateAtItem.refreshTask = itItem->refreshTask;
                updateAtItem.updateAtTime = itItem->updateAtTime;
                HILOG_INFO("get update at timer successfully");
                return true;
            }
        }
    }
    HILOG_INFO("update at timer not find");
    return false;
}
/**
 * @brief Get dynamic refresh item.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::GetDynamicItem(int64_t formId, DynamicRefreshItem &dynamicItem)
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
        std::list<DynamicRefreshItem>::iterator itItem;
        for (itItem = dynamicRefreshTasks_.begin(); itItem != dynamicRefreshTasks_.end();) {
            if (itItem->formId == formId) {
                dynamicItem.formId = itItem->formId;
                dynamicItem.settedTime = itItem->settedTime;
                dynamicItem.userId = itItem->userId;
                return true;
            }
        }
    }
    HILOG_INFO("dynamic item not find");
    return false;
}
/**
 * @brief Set time speed.
 * @param timeSpeed The time speed.
 */
void FormTimerMgr::SetTimeSpeed(int32_t timeSpeed)
{
    HILOG_INFO("set time speed to:%{public}d", timeSpeed);
    timeSpeed_ = timeSpeed;
    HandleResetLimiter();
    ClearIntervalTimer();
}
/**
 * @brief Delete interval timer task.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::DeleteIntervalTimer(int64_t formId)
{
    HILOG_INFO("start");
    bool isExist = false;

    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    auto intervalTask = intervalTimerTasks_.find(formId);
    if (intervalTask != intervalTimerTasks_.end()) {
        intervalTimerTasks_.erase(intervalTask);
        isExist = true;
    }

    if (intervalTimerTasks_.empty() && (intervalTimerId_ != 0L)) {
        InnerClearIntervalTimer();
    }
    HILOG_INFO("end");
    return isExist;
}
/**
 * @brief Delete update at timer.
 * @param formId The Id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::DeleteUpdateAtTimer(int64_t formId)
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::mutex> lock(updateAtMutex_);
        std::list<UpdateAtItem>::iterator itItem;
        for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end(); itItem++) {
            if (itItem->refreshTask.formId == formId) {
                updateAtTimerTasks_.erase(itItem);
                break;
            }
        }
    }

    if (!UpdateAtTimerAlarm()) {
        HILOG_ERROR("updateAtTimerAlarm failed");
        return false;
    }
    return true;
}
/**
 * @brief Delete dynamic refresh item.
 * @param formId The Id of the form.
 */
bool FormTimerMgr::DeleteDynamicItem(int64_t formId)
{
    HILOG_INFO("start");
    {
        std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
        std::list<DynamicRefreshItem>::iterator itItem;
        for (itItem = dynamicRefreshTasks_.begin(); itItem != dynamicRefreshTasks_.end();) {
            if (itItem->formId == formId) {
                itItem = dynamicRefreshTasks_.erase(itItem);
                if (itItem != dynamicRefreshTasks_.end()) {
                    SetIntervalEnableFlag(itItem->formId, true);
                }
                break;
            }
            ++itItem;
        }
        dynamicRefreshTasks_.sort(CompareDynamicRefreshItem);
    }

    if (!UpdateDynamicAlarm()) {
        HILOG_ERROR("fail UpdateDynamicAlarm");
        return false;
    }
    return true;
}
/**
* @brief interval timer task timeout.
*/
void FormTimerMgr::OnIntervalTimeOut()
{
    HILOG_INFO("start");
    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    std::vector<FormTimer> updateList;
    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    for (auto &intervalPair : intervalTimerTasks_) {
        FormTimer &intervalTask = intervalPair.second;
        HILOG_BRIEF("intervalTask formId:%{public}" PRId64 ", period:%{public}" PRId64 ""
            "currentTime:%{public}" PRId64 ", refreshTime:%{public}" PRId64 ", isEnable:%{public}d",
            intervalTask.formId, intervalTask.period, currentTime,
            intervalTask.refreshTime, intervalTask.isEnable);
        if (!((currentTime - intervalTask.refreshTime) >= intervalTask.period ||
            std::abs((currentTime - intervalTask.refreshTime) - intervalTask.period) <
            (Constants::ABS_TIME / timeSpeed_))) {
            continue;
        }

        // Verify if the next refresh will expire
        if (!intervalTask.isEnable) {
            bool isDynamicTimerExpired = IsDynamicTimerExpired(intervalTask.formId);
            if (isDynamicTimerExpired) {
                intervalTask.isEnable = true;
            } else {
                continue;
            }
        }

        if (!refreshLimiter_.IsEnableRefresh(intervalTask.formId)) {
            continue;
        }

        intervalTask.refreshTime = currentTime;
        updateList.emplace_back(intervalTask);
    }

    if (!updateList.empty()) {
        for (auto &task : updateList) {
            task.refreshType = RefreshType::TYPE_INTERVAL;
            ExecTimerTask(task);
        }
    }
    HILOG_INFO("end");
}

/**
 * @brief Update at timer task alarm.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateAtTimerAlarm()
{
    FormTimer timerTask;
    return UpdateAtTimerAlarmDetail(timerTask);
}

int64_t FormTimerMgr::GetBootTimeMs()
{
    int64_t timeNow = -1;
    struct timespec tv {};
    if (clock_gettime(CLOCK_BOOTTIME, &tv) < 0) {
        HILOG_WARN("Get bootTime by clock_gettime failed, use std::chrono::steady_clock");
        auto timeSinceEpoch = std::chrono::steady_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
    }
    timeNow = tv.tv_sec * NANO_TO_SECOND + tv.tv_nsec;
    std::chrono::steady_clock::time_point tp_epoch ((std::chrono::nanoseconds(timeNow)));
    auto timeSinceEpoch = tp_epoch.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timeSinceEpoch).count();
}

/**
 * @brief Get WantAgent.
 * @param updateAtTime The next update time.
 * @return Returns WantAgent.
 */
std::shared_ptr<WantAgent> FormTimerMgr::GetUpdateAtWantAgent(long updateAtTime, int32_t userId)
{
    std::shared_ptr<Want> want = std::make_shared<Want>();
    ElementName element("", "", "");
    want->SetElement(element);
    want->SetAction(Constants::ACTION_UPDATEATTIMER);
    want->SetParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_STATIC_UPDATE);
    want->SetParam(Constants::KEY_WAKEUP_TIME, updateAtTime);

    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.emplace_back(want);
    WantAgentInfo wantAgentInfo(REQUEST_UPDATE_AT_CODE, WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        WantAgentConstant::Flags::CANCEL_PRESENT_FLAG, wants, nullptr);
    return IN_PROCESS_CALL(WantAgentHelper::GetWantAgent(wantAgentInfo, userId));
}

/**
 * @brief Clear update at timer resource.
 */
void FormTimerMgr::ClearUpdateAtTimerResource()
{
    HILOG_INFO("start");
    if (updateAtTimerId_ != 0L) {
        HILOG_INFO("clear update at timer start");
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(updateAtTimerId_);
        HILOG_INFO("clear update at timer end");
        updateAtTimerId_ = 0L;
    }
    if (currentUpdateAtWantAgent_ != nullptr) {
        IN_PROCESS_CALL(WantAgentHelper::Cancel(currentUpdateAtWantAgent_));
        currentUpdateAtWantAgent_ = nullptr;
    }
    HILOG_INFO("end");
}

/**
 * @brief Update limiter task alarm.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateLimiterAlarm()
{
    HILOG_INFO("start");
    if (limiterTimerId_ != 0L) {
        HILOG_INFO("stop limiter timer start");
        int32_t retCode = MiscServices::TimeServiceClient::GetInstance()->StopTimerV9(limiterTimerId_);
        if (retCode == MiscServices::E_TIME_DEAL_FAILED) {
            HILOG_WARN("reset limiter timer");
            limiterTimerId_ = 0L;
        }
        HILOG_INFO("stop limiter timer end");
    }

    // make limiter wakeup time
    struct tm tmAtTime = {0};
    auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm* ptm = localtime_r(&tt, &tmAtTime);
    if (ptm == nullptr) {
        HILOG_ERROR("localtime error");
        return false;
    }
    tmAtTime.tm_sec = Constants::MAX_SECOND; // max value can be 61
    tmAtTime.tm_hour = Constants::MAX_HOUR;
    tmAtTime.tm_min = Constants::MAX_MINUTE;
    int64_t limiterWakeUpTime = FormUtil::GetMillisecondFromTm(tmAtTime);

    if (!CreateLimiterTimer()) {
        return false;
    }
    bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(limiterTimerId_,
        static_cast<uint64_t>(limiterWakeUpTime));
    if (!bRet) {
        HILOG_ERROR("init limiter timer task error");
        return false;
    }
    HILOG_INFO("end");
    return true;
}
/**
 * @brief Clear limiter timer resource.
 */
void FormTimerMgr::ClearLimiterTimerResource()
{
    HILOG_INFO("start");
    if (limiterTimerId_ != 0L) {
        HILOG_INFO("clear limiter timer start");
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(limiterTimerId_);
        HILOG_INFO("clear limiter timer end");
        limiterTimerId_ = 0L;
    }

    if (currentLimiterWantAgent_ != nullptr) {
        IN_PROCESS_CALL(WantAgentHelper::Cancel(currentLimiterWantAgent_));
        currentLimiterWantAgent_ = nullptr;
    }
    HILOG_INFO("end");
}

bool FormTimerMgr::CreateLimiterTimer()
{
    HILOG_INFO("start");
    auto timerOption = std::make_shared<FormTimerOption>();
    timerOption->SetType(timerOption->TIMER_TYPE_EXACT);
    timerOption->SetRepeat(false);
    timerOption->SetInterval(0);
    std::shared_ptr<WantAgent> wantAgent = GetLimiterWantAgent();
    if (!wantAgent) {
        HILOG_ERROR("create wantAgent failed");
        return false;
    }
    timerOption->SetWantAgent(wantAgent);
    if (limiterTimerId_ == 0L) {
        limiterTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
        HILOG_INFO("new timerId:%{public}" PRId64 ".", limiterTimerId_);
        currentLimiterWantAgent_ = wantAgent;
    }
    HILOG_INFO("end");
    return true;
}

/**
 * @brief Get WantAgent.
 * @return Returns WantAgent.
 */
std::shared_ptr<WantAgent> FormTimerMgr::GetLimiterWantAgent()
{
    std::shared_ptr<Want> want = std::make_shared<Want>();
    ElementName element("", "", "");
    want->SetElement(element);
    want->SetAction(Constants::ACTION_UPDATEATTIMER);
    want->SetParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_RESET_LIMIT);

    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.emplace_back(want);
    WantAgentInfo wantAgentInfo(REQUEST_LIMITER_CODE, WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        WantAgentConstant::Flags::UPDATE_PRESENT_FLAG, wants, nullptr);
    return IN_PROCESS_CALL(WantAgentHelper::GetWantAgent(wantAgentInfo));
}

/**
 * @brief Update dynamic refresh task alarm.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::UpdateDynamicAlarm()
{
    HILOG_INFO("start");
    std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
    if (dynamicRefreshTasks_.empty()) {
        ClearDynamicResource();
        dynamicWakeUpTime_ = INT64_MAX;
        return true;
    }

    if (!IsNeedUpdate()) {
        HILOG_ERROR("no need to UpdateDynamicAlarm");
        return true;
    }

    auto firstTask = dynamicRefreshTasks_.begin();
    auto timerOption = std::make_shared<FormTimerOption>();
    timerOption->SetType(((unsigned int)(timerOption->TIMER_TYPE_REALTIME))
     | ((unsigned int)(timerOption->TIMER_TYPE_EXACT)));
    timerOption->SetRepeat(false);
    timerOption->SetInterval(0);
    std::shared_ptr<WantAgent> wantAgent = GetDynamicWantAgent(dynamicWakeUpTime_, firstTask->userId);
    if (!wantAgent) {
        HILOG_ERROR("create wantAgent failed");
        return false;
    }
    timerOption->SetWantAgent(wantAgent);

    if (currentDynamicWantAgent_ != nullptr) {
        ClearDynamicResource();
    }
    currentDynamicWantAgent_ = wantAgent;

    dynamicAlarmTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
    bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(dynamicAlarmTimerId_,
        static_cast<uint64_t>(dynamicWakeUpTime_));
    if (!bRet) {
        HILOG_ERROR("init dynamic timer task error");
    }
    HILOG_INFO("dynamicWakeUpTime_:%{public}" PRId64, dynamicWakeUpTime_);
    return true;
}

bool FormTimerMgr::IsNeedUpdate()
{
    auto firstTask = dynamicRefreshTasks_.begin();
    if (dynamicWakeUpTime_ != firstTask->settedTime) {
        dynamicWakeUpTime_ = firstTask->settedTime;
        return true;
    }
    if (dynamicWakeUpTime_ == firstTask->settedTime &&
        GetBootTimeMs() - Constants::ABS_REFRESH_MS > dynamicWakeUpTime_) {
        HILOG_WARN("invalid dynamicWakeUpTime_ less than currentTime, remove it");
        firstTask = dynamicRefreshTasks_.erase(dynamicRefreshTasks_.begin());
        if (firstTask == dynamicRefreshTasks_.end()) {
            return false;
        }
        dynamicWakeUpTime_ = firstTask->settedTime;
        return true;
    }
    return false;
}

/**
 * @brief Get WantAgent.
 * @param nextTime The next update time.
 * @return Returns WantAgent.
 */
std::shared_ptr<WantAgent> FormTimerMgr::GetDynamicWantAgent(int64_t nextTime, int32_t userId)
{
    std::shared_ptr<Want> want = std::make_shared<Want>();
    ElementName element("", "", "");
    want->SetElement(element);
    want->SetAction(Constants::ACTION_UPDATEATTIMER);
    want->SetParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_DYNAMIC_UPDATE);
    int nextTimeRight = static_cast<int>(nextTime);
    int nextTimLeft = static_cast<int>(static_cast<uint64_t>(nextTime) >> SHIFT_BIT_LENGTH);

    want->SetParam(Constants::KEY_WAKEUP_TIME_LEFT, nextTimLeft);
    want->SetParam(Constants::KEY_WAKEUP_TIME_RIGHT, nextTimeRight);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.emplace_back(want);
    WantAgentInfo wantAgentInfo(REQUEST_DYNAMIC_CODE, WantAgentConstant::OperationType::SEND_COMMON_EVENT,
        WantAgentConstant::Flags::CANCEL_PRESENT_FLAG, wants, nullptr);
    return IN_PROCESS_CALL(WantAgentHelper::GetWantAgent(wantAgentInfo, userId));
}

/**
 * @brief Clear dynamic refresh resource.
 */
void FormTimerMgr::ClearDynamicResource()
{
    HILOG_INFO("start");
    if (dynamicAlarmTimerId_ != 0L) {
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(dynamicAlarmTimerId_);
        HILOG_INFO("clear dynamic timer end");
        dynamicAlarmTimerId_ = 0L;
    }

    if (currentDynamicWantAgent_ != nullptr) {
        IN_PROCESS_CALL(WantAgentHelper::Cancel(currentDynamicWantAgent_));
        currentDynamicWantAgent_ = nullptr;
        HILOG_INFO("Cancel");
    }
}
/**
 * @brief Find next at timer item.
 * @param nowTime Update time.
 * @param updateAtItem Next at timer item.
 * @return Returns true on success, false on failure.
 */
bool FormTimerMgr::FindNextAtTimerItem(long nowTime, UpdateAtItem &updateAtItem)
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(updateAtMutex_);
    if (updateAtTimerTasks_.empty()) {
        HILOG_WARN("empty updateAtTimerTasks_");
        return false;
    }

    std::list<UpdateAtItem>::iterator itItem;
    for (itItem = updateAtTimerTasks_.begin(); itItem != updateAtTimerTasks_.end(); itItem++) {
        if (itItem->updateAtTime > nowTime) {
            updateAtItem = *itItem;
            break;
        }
    }

    if (itItem == updateAtTimerTasks_.end()) {
        updateAtItem = updateAtTimerTasks_.front();
    }
    HILOG_INFO("end");
    return true;
}

/**
 * @brief Ensure init interval timer resource.
 */
void FormTimerMgr::EnsureInitIntervalTimer()
{
    HILOG_INFO("init base timer task");
    if (intervalTimerId_ != 0L) {
        return;
    }

    HILOG_INFO("Create intervalTimer");
    // 1. Create Timer Option
    auto timerOption = std::make_shared<FormTimerOption>();
    int32_t flag = ((unsigned int)(timerOption->TIMER_TYPE_REALTIME))
      | ((unsigned int)(timerOption->TIMER_TYPE_EXACT));
    timerOption->SetType(flag);
    timerOption->SetRepeat(true);
    int64_t interval = TIMER_UPDATE_INTERVAL / timeSpeed_;
    timerOption->SetInterval(interval);
    auto timeCallback = []() { FormTimerMgr::GetInstance().OnIntervalTimeOut(); };
    timerOption->SetCallbackInfo(timeCallback);

    // 2. Create Timer and get TimerId
    intervalTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
    int64_t timeInSec = GetBootTimeMs();
    HILOG_INFO("TimerId:%{public}" PRId64 ", timeInSec:%{public}" PRId64 ", interval:%{public}" PRId64,
        intervalTimerId_, timeInSec, interval);

    // 3. Start Timer
    int64_t startTime = timeInSec + interval;
    bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(intervalTimerId_,
        static_cast<uint64_t>(startTime));
    if (!bRet) {
        HILOG_ERROR("init intervalTimer task error");
        InnerClearIntervalTimer();
    }
    HILOG_INFO("end");
}

void FormTimerMgr::FormPeriodReport()
{
    HILOG_INFO("init base Refresh count task");
    if (limiterTimerReportId_ != 0L) {
        return;
    }
    auto timerOption = std::make_shared<FormTimerOption>();
    int32_t flag = ((unsigned int)(timerOption->TIMER_TYPE_REALTIME))
      | ((unsigned int)(timerOption->TIMER_TYPE_EXACT));
    timerOption->SetType(flag);
    timerOption->SetRepeat(true);
    int64_t interval = Constants::MS_PER_DAY / timeSpeed_;
    timerOption->SetInterval(interval);
    auto timeCallback = []() {
        FormRecordReport::GetInstance().HandleFormRefreshCount();
        FormRenderReport::GetInstance().ReportFRSStatus();
    };
    timerOption->SetCallbackInfo(timeCallback);
    limiterTimerReportId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
    int64_t timeInSec = GetBootTimeMs();
    HILOG_INFO("TimerId:%{public}" PRId64 ", timeInSec:%{public}" PRId64 ", interval:%{public}" PRId64 ".",
        limiterTimerReportId_, timeInSec, interval);
    int64_t startTime = timeInSec + interval;
    bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(limiterTimerReportId_,
        static_cast<uint64_t>(startTime));
    if (!bRet) {
        HILOG_ERROR("init limiterTimerReport task error");
        InnerClearIntervalReportTimer();
    }
    HILOG_INFO("Create intervalTimer end");
}

void FormTimerMgr::StartDiskUseInfoReportTimer()
{
    HILOG_INFO("start disk use report Timer");
    if (reportDiskUseTimerId_ != 0L) {
        return;
    }
    auto timerOption = std::make_shared<FormTimerOption>();
    unsigned int flag = ((unsigned int)(timerOption->TIMER_TYPE_REALTIME)) |
        ((unsigned int)(timerOption->TIMER_TYPE_EXACT));
    timerOption->SetType((int)flag);
    timerOption->SetRepeat(true);
    int64_t interval = Constants::MS_PER_DAY;
    timerOption->SetInterval(interval);
    auto timeCallback = []() { FormEventReport::SendDiskUseEvent(); };
    timerOption->SetCallbackInfo(timeCallback);
    reportDiskUseTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
    if (reportDiskUseTimerId_ <= 0) {
        HILOG_ERROR("invalid reportDiskUseTimerId_:%{public}" PRId64 ".", reportDiskUseTimerId_);
        return;
    }
    int64_t timeInSec = GetBootTimeMs();
    HILOG_INFO("TimerId:%{public}" PRId64 ", timeInSec:%{public}" PRId64 ", interval:%{public}" PRId64 ".",
        reportDiskUseTimerId_, timeInSec, interval);
    int64_t startTime = timeInSec + interval;
    bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(reportDiskUseTimerId_,
        static_cast<uint64_t>(startTime));
    if (!bRet) {
        HILOG_ERROR("start disk use report Timer error");
        ClearDiskInfoReportTimer();
    }
    HILOG_INFO("report disk use info  end");
}
/**
 * @brief Clear interval timer resource.
 */
void FormTimerMgr::ClearIntervalTimer()
{
    HILOG_INFO("start");
    std::lock_guard<std::recursive_mutex> lock(intervalMutex_);
    InnerClearIntervalTimer();
    InnerClearIntervalReportTimer();
    HILOG_INFO("end");
}

void FormTimerMgr::InnerClearIntervalTimer()
{
    HILOG_INFO("start");
    if (intervalTimerId_ != 0L) {
        HILOG_INFO("Destroy intervalTimer");
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(intervalTimerId_);
        intervalTimerId_ = 0L;
    }
    HILOG_INFO("end");
}

void FormTimerMgr::InnerClearIntervalReportTimer()
{
    HILOG_INFO("start");
    if (limiterTimerReportId_ != 0L) {
        HILOG_INFO("Destroy interval Report Timerr");
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(limiterTimerReportId_);
        limiterTimerReportId_ = 0L;
    }
    HILOG_INFO("end");
}

void FormTimerMgr::ClearDiskInfoReportTimer()
{
    HILOG_INFO("start");
    if (reportDiskUseTimerId_ != 0L) {
        HILOG_INFO("Destroy interval Report Timerr");
        MiscServices::TimeServiceClient::GetInstance()->DestroyTimerAsync(reportDiskUseTimerId_);
        reportDiskUseTimerId_ = 0L;
    }
    HILOG_INFO("end");
}

#ifdef RES_SCHEDULE_ENABLE
/**
 * @brief Execute Form timer task.
 * @param timerTask Form timer task.
 */
void FormTimerMgr::ExecTimerTask(const FormTimer &timerTask)
{
    ExecTimerTaskCore(timerTask);
}

/**
 * @brief Execute Form timer task.
 * @param timerTask Form timer task core.
 */
void FormTimerMgr::ExecTimerTaskCore(const FormTimer &timerTask)
#else
/**
 * @brief Execute Form timer task.
 * @param timerTask Form timer task.
 */
void FormTimerMgr::ExecTimerTask(const FormTimer &timerTask)
#endif // RES_SCHEDULE_ENABLE
{
    HILOG_BRIEF("userId:%{public}d", timerTask.userId);
    RefreshData data;
    data.formId = timerTask.formId;
    data.formTimer = timerTask;
    FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_TIMER);
}

/**
 * @brief Init.
 */
void FormTimerMgr::Init()
{
    HILOG_INFO("start");
    systemTimerEventReceiver_ = nullptr;
    EventFwk::MatchingSkills systemEventMatchingSkills;
    systemEventMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    systemEventMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
#ifdef FORM_EVENT_FOR_TEST
    systemEventMatchingSkills.AddEvent(FMS_TIME_SPEED);
#endif
    EventFwk::CommonEventSubscribeInfo systemTimerEventSubInfo(systemEventMatchingSkills);
    systemTimerEventSubInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    systemTimerEventReceiver_ = std::make_shared<TimerReceiver>(systemTimerEventSubInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(systemTimerEventReceiver_);

    // Custom timer event need to set specified publisher uid
    customTimerEventReceiver_ = nullptr;
    EventFwk::MatchingSkills customEventMatchingSkills;
    customEventMatchingSkills.AddEvent(Constants::ACTION_UPDATEATTIMER);
    EventFwk::CommonEventSubscribeInfo customTimerEventSubInfo(customEventMatchingSkills);
    customTimerEventSubInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    customTimerEventSubInfo.SetPublisherUid(FOUNDATION_UID);
    customTimerEventReceiver_ = std::make_shared<TimerReceiver>(customTimerEventSubInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(customTimerEventReceiver_);

    intervalTimerId_ = 0L;
    updateAtTimerId_ = 0L;
    dynamicAlarmTimerId_ = 0L;
    limiterTimerId_ = 0L;
    limiterTimerReportId_ = 0L;
    reportDiskUseTimerId_ = 0L;
    FormPeriodReport();
    CreateLimiterTimer();
    HILOG_INFO("end");
}

/**
 * @brief Receiver Constructor.
 * @param subscriberInfo Subscriber info.
 */
FormTimerMgr::TimerReceiver::TimerReceiver(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{}
/**
 * @brief Receive common event.
 * @param eventData Common event data.
 */
void FormTimerMgr::TimerReceiver::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    AAFwk::Want want = eventData.GetWant();
    std::string action = want.GetAction();

    HILOG_INFO("action:%{public}s", action.c_str());

    if (action == FMS_TIME_SPEED) {
        // Time speed must between 1 and 1000.
        auto timeSpeed = std::clamp(eventData.GetCode(), Constants::MIN_TIME_SPEED, Constants::MAX_TIME_SPEED);
        FormTimerMgr::GetInstance().SetTimeSpeed(timeSpeed);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_TIME_CHANGED
        || action == EventFwk::CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED) {
        FormTimerMgr::GetInstance().HandleSystemTimeChanged();
    } else if (action == Constants::ACTION_UPDATEATTIMER) {
        int type = want.GetIntParam(Constants::KEY_ACTION_TYPE, Constants::TYPE_STATIC_UPDATE);
        if (type == Constants::TYPE_RESET_LIMIT) {
            FormTimerMgr::GetInstance().HandleResetLimiter();
        } else if (type == Constants::TYPE_STATIC_UPDATE) {
            long updateTime = want.GetLongParam(Constants::KEY_WAKEUP_TIME, -1);
            if (updateTime < 0) {
                HILOG_ERROR("invalid updateTime:%{public}ld", updateTime);
                return;
            }
            FormTimerMgr::GetInstance().OnUpdateAtTrigger(updateTime);
        } else if (type == Constants::TYPE_DYNAMIC_UPDATE) {
            int updateTimeLeft = want.GetIntParam(Constants::KEY_WAKEUP_TIME_LEFT, -1);
            int updateTimeRight = want.GetIntParam(Constants::KEY_WAKEUP_TIME_RIGHT, -1);
            int64_t updateTime = static_cast<int64_t>(((static_cast<uint64_t>(updateTimeLeft) <<
                SHIFT_BIT_LENGTH) | static_cast<uint64_t>(updateTimeRight)));
            if (updateTime <= 0) {
                HILOG_ERROR("invalid updateTime:%{public}" PRId64 "", updateTime);
                return;
            }
            FormTimerMgr::GetInstance().OnDynamicTimeTrigger(updateTime);
        } else {
            HILOG_ERROR("invalid type when action is update at timer");
        }
    } else {
        HILOG_ERROR("invalid action");
    }
}
/**
 * @brief check if user is active or not.
 *
 * @param userId User ID.
 * @return true:active, false:inactive
 */
bool FormTimerMgr::IsActiveUser(int32_t userId)
{
    std::vector<int32_t> activeList;
    auto errCode = DelayedSingleton<OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    auto iter = std::find(activeList.begin(), activeList.end(), userId);
    if (iter != activeList.end() && errCode == ERR_OK) {
        return true;
    }
    return false;
}

bool FormTimerMgr::IsDynamicTimerExpired(int64_t formId)
{
    std::lock_guard<std::recursive_mutex> lock(dynamicMutex_);
    auto itItem = std::find_if(dynamicRefreshTasks_.begin(), dynamicRefreshTasks_.end(),
        [formId](const auto &it) { return it.formId == formId; });
    if (itItem == dynamicRefreshTasks_.end()) {
        HILOG_WARN("can't find dynamic refresh task, just restore. formId:%{public}" PRId64, formId);
        return true;
    }

    auto timeInSec = GetBootTimeMs();
    if (itItem->settedTime > timeInSec) {
        HILOG_INFO("dynamic refresh task wait trigger. formId:%{public}" PRId64, formId);
        return false;
    }

    HILOG_WARN("dynamic refresh timed out without triggering. formId:%{public}" PRId64, formId);
    dynamicRefreshTasks_.erase(itItem);
    dynamicRefreshTasks_.sort(CompareDynamicRefreshItem);
    UpdateDynamicAlarm();
    return true;
}

bool FormTimerMgr::UpdateAtTimerAlarmDetail(FormTimer &timerTask)
{
    struct tm tmAtTime = {0};
    auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm* ptm = localtime_r(&tt, &tmAtTime);
    if (ptm == nullptr) {
        HILOG_ERROR("localtime error");
        return false;
    }

    long nowAtTime = tmAtTime.tm_hour * Constants::MIN_PER_HOUR + tmAtTime.tm_min;
    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    UpdateAtItem foundItem;
    bool found = FindNextAtTimerItem(nowAtTime, foundItem);
    if (!found) {
        {
            std::lock_guard<std::mutex> lock(updateAtMutex_);
            if (!updateAtTimerTasks_.empty()) {
                HILOG_WARN("updateAtTimerTasks_ not empty");
                return true;
            }
        }
        {
            std::lock_guard<std::mutex> lock(currentUpdateWantAgentMutex_);
            ClearUpdateAtTimerResource();
        }
        atTimerWakeUpTime_ = LONG_MAX;
        HILOG_INFO("no update at task in system now");
        return true;
    }

    tmAtTime.tm_sec = 0;
    tmAtTime.tm_hour = foundItem.refreshTask.hour;
    tmAtTime.tm_min = foundItem.refreshTask.min;
    int64_t selectTime = FormUtil::GetMillisecondFromTm(tmAtTime);
    int64_t diffTime = selectTime - currentTime;
    // Create updateAt timer that triggers within 10 seconds, request a refresh proactively.
    if (std::abs(diffTime) <= TIMER_UPDATEAT_CREATE_BEHIND_TRIGGER && timerTask.formId > 0) {
        HILOG_WARN("the timer was created late, actively request a refresh. formId:%{public}" PRId64, timerTask.formId);
        timerTask.refreshType = RefreshType::TYPE_UPDATETIMES;
        ExecTimerTask(timerTask);
    }
    if (diffTime < 0) {
        selectTime += Constants::MS_PER_DAY;
    }
    HILOG_INFO("selectTime:%{public}" PRId64 ", currentTime:%{public}" PRId64, selectTime, currentTime);

    int64_t timeInSec = GetBootTimeMs();
    HILOG_INFO("timeInSec:%{public}" PRId64 ".", timeInSec);
    int64_t nextTime = timeInSec + (selectTime - currentTime);
    HILOG_INFO("nextTime:%{public}" PRId64, nextTime);
    if (nextTime == atTimerWakeUpTime_) {
        HILOG_WARN("end, wakeUpTime not change, no need update alarm");
        return true;
    }

    auto timerOption = std::make_shared<FormTimerOption>();
    int32_t flag = ((unsigned int)(timerOption->TIMER_TYPE_REALTIME))
      | ((unsigned int)(timerOption->TIMER_TYPE_EXACT));
    HILOG_DEBUG("timerOption type is %{public}d", flag);
    timerOption->SetType(flag);
    timerOption->SetRepeat(false);
    timerOption->SetInterval(0);
    int32_t userId = foundItem.refreshTask.userId;
    std::shared_ptr<WantAgent> wantAgent = GetUpdateAtWantAgent(foundItem.updateAtTime, userId);
    if (wantAgent == nullptr) {
        HILOG_ERROR("create wantAgent failed");
        return false;
    }
    timerOption->SetWantAgent(wantAgent);

    atTimerWakeUpTime_ = nextTime;
    {
        std::lock_guard<std::mutex> lock(currentUpdateWantAgentMutex_);
        if (currentUpdateAtWantAgent_ != nullptr) {
            ClearUpdateAtTimerResource();
        }
        currentUpdateAtWantAgent_ = wantAgent;
        updateAtTimerId_ = MiscServices::TimeServiceClient::GetInstance()->CreateTimer(timerOption);
        bool bRet = MiscServices::TimeServiceClient::GetInstance()->StartTimer(updateAtTimerId_,
            static_cast<uint64_t>(nextTime));
        if (!bRet) {
            HILOG_ERROR("init update at timer task error");
            return false;
        }
    }

    HILOG_INFO("end");
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
