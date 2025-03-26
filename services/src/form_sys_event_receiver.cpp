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

#include "common/event/system_event/form_sys_event_receiver.h"

#include <cinttypes>

#include "common_event_support.h"
#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_mgr.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_adapter.h"
#include "form_render/form_render_mgr.h"
#include "status_mgr_center/form_serial_queue.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_util.h"
#include "in_process_call_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAIN_USER_ID = 100;
constexpr int32_t TASK_DELAY_TIME = 30; // ms
} // namespace
/**
 * @brief Receiver Constructor.
 * @param subscriberInfo Subscriber info.
 */
FormSysEventReceiver::FormSysEventReceiver(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{}

void FormSysEventReceiver::HandleAbilityUpdate(const AAFwk::Want& want, std::string &bundleName)
{
    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    auto task = [want, bundleName]() {
        HILOG_INFO("bundle updated, bundleName:%{public}s", bundleName.c_str());
        int userId = want.GetIntParam(KEY_USER_ID, 0);
        FormEventUtil::HandleProviderUpdated(bundleName, userId);
    };
    serialQueue_->ScheduleTask(0, task);
}

void FormSysEventReceiver::HandlePackageDataCleared(std::string &bundleName, int32_t userId)
{
    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    auto task = [bundleName, userId]() {
        FormEventUtil::HandleBundleDataCleared(bundleName, userId);
    };
    serialQueue_->ScheduleTask(0, task);
}

void FormSysEventReceiver::HandleScreenUnlocked(int32_t userId)
{
    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    auto task = [userId]() {
        FormRenderMgr::GetInstance().OnScreenUnlock(userId);
    };
    serialQueue_->ScheduleTask(0, task);
}

void FormSysEventReceiver::HandleUserUnlocked(int32_t userId)
{
    if (userId == -1) {
        HILOG_ERROR("invalid userId: -1");
        return;
    }

    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    auto task = [userId]() {
        FormEventUtil::HandleOnUnlock(userId);
    };
    serialQueue_->ScheduleTask(0, task);
}

/**
 * @brief Receive common event.
 * @param eventData Common event data.
 */
void FormSysEventReceiver::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const AAFwk::Want& want = eventData.GetWant();
    std::string action = want.GetAction();
    std::string bundleName = want.GetElement().GetBundleName();
    if (action.empty()) {
        HILOG_ERROR("empty action");
        return;
    }
    if (bundleName.empty() && action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_SECOND_MOUNTED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        HILOG_ERROR("invalid param, action:%{public}s, bundleName:%{public}s",
            action.c_str(), bundleName.c_str());
        return;
    }
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
    HILOG_INFO("action:%{public}s", action.c_str());
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED) {
        HandleAbilityUpdate(want, bundleName);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = eventData.GetCode();
        HandleUserIdRemoved(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED) {
        HandleBundleScanFinished();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        HandleUserSwitched(eventData);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        int userId = want.GetIntParam(KEY_USER_ID, Constants::DEFAULT_USERID);
        HandlePackageDataCleared(bundleName, userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        int userId = want.GetIntParam(KEY_USER_ID, Constants::DEFAULT_USERID);
        // el2 path maybe not unlocked
        HandleScreenUnlocked(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SECOND_MOUNTED) {
        // el2 path is unlocked when receive SECOND_MOUNTED
        int userId = want.GetIntParam(KEY_USER_ID, Constants::DEFAULT_USERID);
        HandleUserUnlocked(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        HandleScreenOn();
    } else {
        HILOG_WARN("invalid action");
    }
}

// multiuser
void FormSysEventReceiver::HandleUserIdRemoved(const int32_t userId)
{
    if (userId == -1) {
        HILOG_ERROR("invalid userId: -1");
        return;
    }

    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    serialQueue_->ScheduleTask(0, [userId]() {
        std::vector<int64_t> removedFormIds;
        FormDataMgr::GetInstance().DeleteFormsByUserId(userId, removedFormIds);
        FormDbCache::GetInstance().DeleteDBFormsByUserId(userId);

        // delete form timer
        std::vector<int64_t>::iterator itRemoved;
        for (itRemoved = removedFormIds.begin(); itRemoved != removedFormIds.end(); ++itRemoved) {
            FormTimerMgr::GetInstance().RemoveFormTimer(*itRemoved);
        }
    });
}

void FormSysEventReceiver::HandleBundleScanFinished()
{
    InitFormInfosAndRegister();
}

void FormSysEventReceiver::InitFormInfosAndRegister()
{
    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    serialQueue_->ScheduleTask(TASK_DELAY_TIME, []() {
        int32_t currUserId = FormUtil::GetCurrentAccountId();
        if (currUserId == Constants::ANY_USERID) {
            HILOG_INFO("use MAIN_USER_ID(%{public}d) instead of current userId: ANY_USERID(%{public}d)",
                MAIN_USER_ID, currUserId);
            currUserId = MAIN_USER_ID;
        }
        FormBmsHelper::GetInstance().RegisterBundleEventCallback();
        if (!FormInfoMgr::GetInstance().HasReloadedFormInfos()) {
            FormInfoMgr::GetInstance().ReloadFormInfos(currUserId);
        }
    });
}

void FormSysEventReceiver::HandleUserSwitched(const EventFwk::CommonEventData &eventData)
{
    int32_t userId = eventData.GetCode();
    if (userId < 0) {
        HILOG_ERROR("invalid switched userId:%{public}d", userId);
        return;
    }

    if (lastUserId_ == 0) {
        HILOG_INFO("reboot init lastUserId");
        lastUserId_ = userId;
        return;
    }

    if (lastUserId_ == userId) {
        HILOG_WARN("same userId");
        return;
    }

    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    int32_t lastUserId = lastUserId_;
    lastUserId_ = userId;
    HILOG_INFO("switch to userId: (%{public}d)", userId);

    serialQueue_->ScheduleTask(0, [userId, lastUserId, this]() {
        if (userId != MAIN_USER_ID) {
            FormInfoMgr::GetInstance().ReloadFormInfos(userId);
        }
    });

    FormTimerMgr::GetInstance().UpdateLimiterAlarm();
    FormTimerMgr::GetInstance().UpdateAtTimerAlarm();
    FormTimerMgr::GetInstance().UpdateDynamicAlarm();
}

void FormSysEventReceiver::HandleScreenOn()
{
    if (!serialQueue_) {
        HILOG_ERROR("null serialQueue");
        return;
    }

    serialQueue_->ScheduleTask(0, []() {
        FormRenderMgr::GetInstance().NotifyScreenOn();
    });
}

void FormSysEventReceiver::RecycleForms(int32_t userId)
{
    std::vector<int64_t> formIds;
    FormDataMgr::GetInstance().GetFormIdsByUserId(userId, formIds);
    Want want;
    want.SetParam(Constants::RECYCLE_FORMS_USER_ID, userId);
    FormMgrAdapter::GetInstance().RecycleForms(formIds, want, false);
}
}  // namespace AppExecFwk
}  // namespace OHOS
