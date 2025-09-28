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

#include <cinttypes>

#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#include "data_center/form_record/form_record_report.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Add form limit info by formId.
 * @param formId The id of the form.
 * @return Returns true on success, false on failure.
 */
bool FormRefreshLimiter::AddItem(const int64_t formId)
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info == limiterMap_.end()) {
        LimitInfo limitInfo;
        auto retVal = limiterMap_.emplace(formId, limitInfo);
        HILOG_INFO("end");
        return retVal.second;
    } else {
        HILOG_INFO("already exist");
        return true;
    }
}
/**
 * @brief Delete form limit info by formId.
 * @param formId The form id.
 */
void FormRefreshLimiter::DeleteItem(const int64_t formId)
{
    HILOG_INFO("delete item");
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info != limiterMap_.end()) {
        limiterMap_.erase(formId);
    }
}
/**
 * @brief Reset limit info.
 */
void FormRefreshLimiter::ResetLimit()
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(limiterMutex_);
    for (auto &infoPair : limiterMap_) {
        infoPair.second.refreshCount = 0;
        infoPair.second.isReported = false;
        infoPair.second.remindFlag = false;
    }
}
/**
 * @brief Refresh enable or not.
 * @param formId The form id.
 * @return Returns ERR_OK on success, others on failure.
 */
bool FormRefreshLimiter::IsEnableRefresh(const int64_t formId)
{
    HILOG_DEBUG("start");
    bool isEnable = false;
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info != limiterMap_.end()) {
        HILOG_INFO("refreshCount:%{public}d, formId:%{public}" PRId64, info->second.refreshCount, formId);
        if (info->second.refreshCount < Constants::LIMIT_COUNT) {
            FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_HIGH_FREQUENCY);
            isEnable = true;
        }

        if (info->second.refreshCount == Constants::LIMIT_COUNT && !info->second.isReported) {
            info->second.isReported = true;
            HILOG_INFO("report refresh to 50 count, formId:%{public}" PRId64 "", formId);
        }
    }
    HILOG_DEBUG("end");
    return isEnable;
}
/**
 * @brief Get refresh count.
 * @param formId The form id.
 * @return refresh count.
 */
int FormRefreshLimiter::GetRefreshCount(const int64_t formId) const
{
    HILOG_INFO("start");
    // -1 means not added or already removed.
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info != limiterMap_.end()) {
        return info->second.refreshCount;
    }

    HILOG_INFO("end");
    return -1;
}
/**
 * @brief Increase refresh count.
 * @param formId The form id.
 */
void FormRefreshLimiter::Increase(const int64_t formId)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info != limiterMap_.end()) {
        info->second.refreshCount++;
        HILOG_INFO("increase,formId:%{public}" PRId64 ", count:%{public}d", formId, info->second.refreshCount);
        if (info->second.refreshCount == Constants::LIMIT_COUNT && !info->second.isReported) {
            info->second.isReported = true;
            HILOG_INFO("report refresh to 50 count,formId:%{public}" PRId64 "", formId);
        }
    }
    HILOG_INFO("end");
}
/**
 * @brief Mark remind flag.
 * @param formId The form id.
 */
void FormRefreshLimiter::MarkRemind(const int64_t formId)
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(limiterMutex_);
    auto info = limiterMap_.find(formId);
    if (info != limiterMap_.end()) {
        if (info->second.refreshCount >= Constants::LIMIT_COUNT) {
            info->second.remindFlag = true;
        }
    }
    HILOG_INFO("end");
}
/**
 * @brief Get remind list.
 * @return remind list.
 */
std::vector<int64_t> FormRefreshLimiter::GetRemindList() const
{
    HILOG_INFO("start");
    std::vector<int64_t> result;
    std::lock_guard<std::mutex> lock(limiterMutex_);
    for (auto &infoPair : limiterMap_) {
        if (infoPair.second.remindFlag) {
            result.emplace_back(infoPair.first);
        }
    }
    HILOG_INFO("end");
    return result;
}
/**
 * @brief Get remind list and reset limit.
 * @return remind list.
 */
std::vector<int64_t> FormRefreshLimiter::GetRemindListAndResetLimit()
{
    HILOG_INFO("start");
    std::vector<int64_t> result;
    std::lock_guard<std::mutex> lock(limiterMutex_);
    for (auto &infoPair : limiterMap_) {
        if (infoPair.second.remindFlag) {
            result.emplace_back(infoPair.first);
        }

        infoPair.second.refreshCount = 0;
        infoPair.second.isReported = false;
        infoPair.second.remindFlag = false;
    }
    HILOG_INFO("end");
    return result;
}
/**
 * @brief Get item count.
 * @return Item count.
 */
int FormRefreshLimiter::GetItemCount() const
{
    std::lock_guard<std::mutex> lock(limiterMutex_);
    return limiterMap_.size();
}
}  // namespace AppExecFwk
}  // namespace OHOS
