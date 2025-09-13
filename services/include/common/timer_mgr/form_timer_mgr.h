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

#ifndef OHOS_FORM_FWK_FORM_TIMER_MGR_H
#define OHOS_FORM_FWK_FORM_TIMER_MGR_H

#include <list>
#include <map>
#include <mutex>
#include <singleton.h>
#include <vector>

#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "ffrt.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#include "common/timer_mgr/form_timer.h"
#include "timer.h"
#include "want_agent.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AbilityRuntime::WantAgent;
/**
 * @class FormTimerMgr
 * form timer task manager.
 */
class FormTimerMgr final : public DelayedRefSingleton<FormTimerMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormTimerMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormTimerMgr);
    /**
     * @brief Add form timer by timer task.
     * @param task The form timer task.
     * @return Returns true on success, false on failure.
     */
    bool AddFormTimer(const FormTimer &task);
    /**
     * @brief Add duration form timer.
     * @param formId The Id of the form.
     * @param updateDuration Update duration.
     * @param userId User ID.
     * @return Returns true on success, false on failure.
     */
    bool AddFormTimer(int64_t formId, long updateDuration, int32_t userId = 0);
    /**
     * @brief Add scheduled form timer.
     * @param formId The Id of the form.
     * @param updateAtHour Hour
     * @param updateAtMin Min
     * @param userId User ID.
     * @return Returns true on success, false on failure.
     */
    bool AddFormTimer(int64_t formId, long updateAtHour, long updateAtMin, int32_t userId = 0);

    /**
     * @brief Add scheduled form timer.
     * @param formId The Id of the form.
     * @param updateAtTimes multi updatetime.
     * @param userId User ID.
     * @return Returns true on success, false on failure.
     */
    bool AddFormTimerForMultiUpdate(int64_t formId, std::vector<std::vector<int>> updateAtTimes, int32_t userId = 0);

    /**
     * @brief Remove form timer by form id.
     * @param formId The Id of the form.
     * @return Returns true on success, false on failure.
     */
    bool RemoveFormTimer(int64_t formId);
    /**
     * @brief Update form timer.
     * @param formId The Id of the form.
     * @param type Timer type.
     * @param timerCfg Timer config.
     * @return Returns true on success, false on failure.
     */
    bool UpdateFormTimer(int64_t formId, const UpdateType &type, const FormTimerCfg &timerCfg);
    /**
     * @brief Is limiter enable refresh.
     * @param formId The Id of the form.
     * @return Returns true on success, false on failure.
     */
    bool IsLimiterEnableRefresh(int64_t formId);
    /**
     * @brief Increase refresh count.
     * @param formId The Id of the form.
     */
    void IncreaseRefreshCount(int64_t formId);
    /**
     * @brief Set next refresh time.
     * @param formId The Id of the form.
     * @param nextGapTime Next gap time.
     * @param userId User ID.
     * @return Returns true on success, false on failure.
     */
    bool SetNextRefreshTime(int64_t formId, long nextGapTime, int32_t userId = 0);
    /**
     * @brief Get refresh count.
     * @param formId The Id of the form.
     * @return Returns refresh count.
     */
    int GetRefreshCount(int64_t formId) const;
    /**
     * @brief Mark remind.
     * @param formId The Id of the form.
     * @return true or false.
     */
    void MarkRemind(int64_t formId);

    /**
     * @brief Handle system time changed.
     * @return Returns true on success, false on failure.
     */
    bool HandleSystemTimeChanged();
    /**
     * @brief Reset form limiter.
     * @return Returns true on success, false on failure.
     */
    bool HandleResetLimiter();
    /**
     * @brief Update at time trigger.
     * @param updateTime Update time.
     * @return Returns true on success, false on failure.
     */
    bool OnUpdateAtTrigger(long updateTime);
    /**
     * @brief Dynamic time trigger.
     * @param updateTime Update time.
     * @return Returns true on success, false on failure.
     */
    bool OnDynamicTimeTrigger(int64_t updateTime);
    /**
     * @brief Get interval timer task.
     * @param formId The Id of the form.
     * @param formTimer update timer.
     * @return Returns true on success, false on failure.
     */
    bool GetIntervalTimer(int64_t formId, FormTimer &formTimer);
    /**
     * @brief Get update at timer.
     * @param formId The Id of the form.
     * @param updateAtItem update timer.
     * @return Returns true on success, false on failure.
     */
    bool GetUpdateAtTimer(int64_t formId, UpdateAtItem &updateAtItem);
    /**
     * @brief Get dynamic refresh item.
     * @param formId The Id of the form.
     * @param dynamicItem update timer.
     * @return Returns true on success, false on failure.
     */
    bool GetDynamicItem(int64_t formId, DynamicRefreshItem &dynamicItem);
    /**
     * @brief Set time speed.
     * @param timeSpeed The time speed.
     */
    void SetTimeSpeed(int32_t timeSpeed);
    /**
     * @brief Update at timer task alarm.
     * @return Returns true on success, false on failure.
     */
    bool UpdateAtTimerAlarm();
    /**
     * @brief Update limiter task alarm.
     * @return Returns true on success, false on failure.
     */
    bool UpdateLimiterAlarm();
    /**
     * @brief Update dynamic refresh task alarm.
     * @return Returns true on success, false on failure.
     */
    bool UpdateDynamicAlarm();
    /**
     * @brief per 24h report disk use info.
     */
    void StartDiskUseInfoReportTimer();

private:
    /**
     * @brief Add update at timer.
     * @param task Update time task.
     * @return Returns true on success, false on failure.
     */
    bool AddUpdateAtTimer(const FormTimer &task);
    /**
     * @brief Add update at timer item.
     * @param atItem Update at timer item.
     */
    void AddUpdateAtItem(const UpdateAtItem &atItem);
    /**
     * @brief Add update interval timer task.
     * @param task Update interval timer task.
     * @return Returns true on success, false on failure.
     */
    bool AddIntervalTimer(const FormTimer &task);
    /**
     * @brief interval timer task timeout.
     */
    void OnIntervalTimeOut();
    /**
     * @brief Get remind tasks.
     * @param remindTasks Remind tasks.
     * @return Returns true on success, false on failure.
     */
    bool GetRemindTasks(std::vector<FormTimer> &remindTasks);
    /**
     * @brief Set enableFlag for interval timer task.
     * @param formId The Id of the form.
     * @param flag Enable flag.
     */
    void SetIntervalEnableFlag(int64_t formId, bool flag);
    /**
     * @brief Update Interval timer task value.
     * @param formId The Id of the form.
     * @param timerCfg task value.
     * @return Returns true on success, false on failure.
     */
    bool UpdateIntervalValue(int64_t formId, const FormTimerCfg &timerCfg);
    /**
     * @brief Update update at timer task value.
     * @param formId The Id of the form.
     * @param timerCfg task value.
     * @return Returns true on success, false on failure.
     */
    bool UpdateAtTimerValue(int64_t formId, const FormTimerCfg &timerCfg);
    /**
     * @brief Interval timer task to update at timer task.
     * @param formId The Id of the form.
     * @param timerCfg task value.
     * @return Returns true on success, false on failure.
     */
    bool IntervalToAtTimer(int64_t formId, const FormTimerCfg &timerCfg);
    /**
     * @brief Update at timer task to interval timer task.
     * @param formId The Id of the form.
     * @param timerCfg task value.
     * @return Returns true on success, false on failure.
     */
    bool AtTimerToIntervalTimer(int64_t formId, const FormTimerCfg &timerCfg);
    /**
     * @brief Delete interval timer task.
     * @param formId The Id of the form.
     * @return Returns true on success, false on failure.
     */
    bool DeleteIntervalTimer(int64_t formId);
    /**
     * @brief Delete update at timer.
     * @param formId The Id of the form.
     * @return Returns true on success, false on failure.
     */
    bool DeleteUpdateAtTimer(int64_t formId);
    /**
     * @brief Clear limiter timer resource.
     */
    void ClearLimiterTimerResource();
    /**
     * @brief Delete dynamic refresh item.
     * @param formId The Id of the form.
     * @return Returns true on success, false on failure.
     */
    bool DeleteDynamicItem(int64_t formId);
    /**
     * @brief Clear dynamic refresh resource.
     */
    void ClearDynamicResource();
    /**
     * @brief Find next at timer item.
     * @param nowTime Update time.
     * @param updateAtItem Next at timer item.
     * @return Returns true on success, false on failure.
     */
    bool FindNextAtTimerItem(long nowTime, UpdateAtItem &updateAtItem);
    /**
     * @brief Clear update at timer resource.
     */
    void ClearUpdateAtTimerResource();

    /**
     * @brief Execute Form timer task.
     * @param task Form timer task.
     */
    void ExecTimerTask(const FormTimer &task);

    /**
     * @brief create limiter timer
     * @return Returns true on success, false on failure.
     */
    bool CreateLimiterTimer();

#ifdef RES_SCHEDULE_ENABLE
    /**
     * @brief Execute Form timer task.
     * @param task Form timer task core.
     */
    void ExecTimerTaskCore(const FormTimer &task);
#endif // RES_SCHEDULE_ENABLE

    /**
     * @brief Init.
     */
    void Init();
    /**
     * @brief Ensure init interval timer resource.
     */
    void EnsureInitIntervalTimer();
    /**
     * @brief Clear interval timer resource.
     */
    void ClearIntervalTimer();
    /**
     * @brief Set enable flag.
     * @param formId The Id of the form.
     * @param flag Enable flag.
     */
    void SetEnableFlag(int64_t formId, bool flag);
    /**
     * @brief Get WantAgent.
     * @param updateAtTime The next update time.
     * @return Returns WantAgent.
     */
    std::shared_ptr<WantAgent> GetUpdateAtWantAgent(long updateAtTime, int32_t userId);
    /**
     * @brief Get WantAgent.
     * @return Returns WantAgent.
     */
    std::shared_ptr<WantAgent> GetLimiterWantAgent();
    /**
     * @brief Get WantAgent.
     * @param nextTime The next update time.
     * @return Returns WantAgent.
     */
    std::shared_ptr<WantAgent> GetDynamicWantAgent(int64_t nextTime, int32_t userId);

    /**
     * @brief check if user is active or not.
     * @param userId User ID.
     * @return true:active, false:inactive
     */
    bool IsActiveUser(int32_t userId);
private:
    /**
     * @class TimerReceiver
     * timer event receiver.
     */
    class TimerReceiver : public EventFwk::CommonEventSubscriber {
    public:
        TimerReceiver() = default;
        TimerReceiver(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
        virtual ~TimerReceiver() = default;
        /**
         * @brief Receive common event.
         * @param eventData Common event data.
         */
        virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;
    };

    struct {
        bool operator()(const DynamicRefreshItem& a, const DynamicRefreshItem& b) const
        {
            return a.settedTime < b.settedTime;
        }
    } CompareDynamicRefreshItem;

    int64_t GetBootTimeMs();

    bool IsNeedUpdate();

    void FormPeriodReport();
    void ClearDiskInfoReportTimer();
    void InnerClearIntervalTimer();
    void InnerClearIntervalReportTimer();
    bool IsDynamicTimerExpired(int64_t formId);
    bool UpdateAtTimerAlarmDetail(FormTimer &timerTask);

    mutable std::recursive_mutex intervalMutex_;
    mutable std::mutex updateAtMutex_;
    mutable std::recursive_mutex dynamicMutex_;
    FormRefreshLimiter refreshLimiter_;
    std::map<int64_t, FormTimer> intervalTimerTasks_;
    std::list<UpdateAtItem> updateAtTimerTasks_;
    std::list<DynamicRefreshItem> dynamicRefreshTasks_;
    std::shared_ptr<TimerReceiver> systemTimerEventReceiver_ = nullptr;
    std::shared_ptr<TimerReceiver> customTimerEventReceiver_ = nullptr;
    int32_t timeSpeed_ = 1;

    uint64_t intervalTimerId_ = 0L;
    uint64_t updateAtTimerId_ = 0L;
    uint64_t dynamicAlarmTimerId_ = 0L;
    uint64_t limiterTimerId_ = 0L;
    uint64_t limiterTimerReportId_ = 0L;
    uint64_t reportDiskUseTimerId_ = 0L;

    mutable std::mutex currentLimiterWantAgentMutex_;
    mutable std::mutex currentUpdateWantAgentMutex_;
    std::shared_ptr<WantAgent> currentUpdateAtWantAgent_ = nullptr;
    std::shared_ptr<WantAgent> currentDynamicWantAgent_ = nullptr;
    std::shared_ptr<WantAgent> currentLimiterWantAgent_ = nullptr;

    int64_t dynamicWakeUpTime_ = INT64_MAX;
    long atTimerWakeUpTime_ = LONG_MAX;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_TIMER_MGR_H
