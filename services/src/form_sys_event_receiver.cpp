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

#include "form_sys_event_receiver.h"

#include <cinttypes>

#include "common_event_support.h"
#include "fms_log_wrapper.h"
#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_db_cache.h"
#include "form_info_mgr.h"
#include "form_render_mgr.h"
#include "form_serial_queue.h"
#include "form_timer_mgr.h"
#include "form_util.h"
#include "in_process_call_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAIN_USER_ID = 100;
constexpr int32_t FORM_TASK_DELAY_TIME = 30; // ms
} // namespace
/**
 * @brief Receiver Constructor.
 * @param subscriberInfo Subscriber info.
 */
FormSysEventReceiver::FormSysEventReceiver(const EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : EventFwk::CommonEventSubscriber(subscriberInfo)
{}

void FormSysEventReceiver::OnReceiveEventForAbilityUpdate(const AAFwk::Want& want, std::string &bundleName)
{
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    auto task = [weakThis, want, bundleName]() {
        HILOG_INFO("bundle updated, bundleName is %{public}s", bundleName.c_str());
        std::shared_ptr<FormSysEventReceiver> sharedThis = weakThis.lock();
        if (sharedThis) {
            int userId = want.GetIntParam(KEY_USER_ID, 0);
            sharedThis->formEventHelper_.HandleProviderUpdated(bundleName, userId);
        }
    };
    serialQueue_->ScheduleTask(0, task);
}

void FormSysEventReceiver::OnReceiveEventForUserRemoved(int32_t userId)
{
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    auto task = [weakThis, userId]() {
        std::shared_ptr<FormSysEventReceiver> sharedThis = weakThis.lock();
        if (sharedThis) {
            sharedThis->HandleUserIdRemoved(userId);
        }
    };
    if (userId != -1) {
        serialQueue_->ScheduleTask(0, task);
    }
}

void FormSysEventReceiver::OnReceiveEventForPackageDataCleared(std::string &bundleName, int32_t userId)
{
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    auto task = [weakThis, bundleName, userId]() {
        std::shared_ptr<FormSysEventReceiver> sharedThis = weakThis.lock();
        if (sharedThis) {
            sharedThis->formEventHelper_.HandleBundleDataCleared(bundleName, userId);
        }
    };
    serialQueue_->ScheduleTask(0, task);
}

void FormSysEventReceiver::OnReceiveEventForUserUnlocked()
{
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    auto task = [weakThis]() {
        std::shared_ptr<FormSysEventReceiver> sharedThis = weakThis.lock();
        if (sharedThis) {
            sharedThis->formEventHelper_.HandleOnUnlock();
        }
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
        HILOG_ERROR("%{public}s failed, empty action", __func__);
        return;
    }
    if (bundleName.empty() && action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        HILOG_ERROR("%{public}s failed, invalid param, action: %{public}s, bundleName: %{public}s",
            __func__, action.c_str(), bundleName.c_str());
        return;
    }
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    HILOG_INFO("%{public}s, action:%{public}s.", __func__, action.c_str());
    std::weak_ptr<FormSysEventReceiver> weakThis = shared_from_this();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_ABILITY_UPDATED) {
        OnReceiveEventForAbilityUpdate(want, bundleName);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        int32_t userId = eventData.GetCode();
        OnReceiveEventForUserRemoved(userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED) {
        HandleBundleScanFinished();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        HandleUserSwitched(eventData);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED) {
        int userId = want.GetIntParam(KEY_USER_ID, Constants::DEFAULT_USERID);
        OnReceiveEventForPackageDataCleared(bundleName, userId);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        OnReceiveEventForUserUnlocked();
    } else {
        HILOG_WARN("%{public}s warnning, invalid action.", __func__);
    }
}

// multiuser
void FormSysEventReceiver::HandleUserIdRemoved(const int32_t userId)
{
    std::vector<int64_t> removedFormIds;
    FormDataMgr::GetInstance().DeleteFormsByUserId(userId, removedFormIds);
    FormDbCache::GetInstance().DeleteDBFormsByUserId(userId);

    // delete form timer
    std::vector<int64_t>::iterator itRemoved;
    for (itRemoved = removedFormIds.begin();itRemoved != removedFormIds.end(); ++itRemoved) {
        FormTimerMgr::GetInstance().RemoveFormTimer(*itRemoved);
    }
}

void FormSysEventReceiver::HandleBundleScanFinished()
{
    InitFormInfosAndRegister();
}

void FormSysEventReceiver::InitFormInfosAndRegister()
{
    if (!serialQueue_) {
        HILOG_ERROR("serialQueue is nullptr!");
        return;
    }

    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, []() {
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
        HILOG_ERROR("invalid switched userId: %{public}d", userId);
        return;
    }

    if (userId == MAIN_USER_ID) {
        HILOG_INFO("main user id has reload");
        return;
    }
    HILOG_INFO("switch to userId: (%{public}d)", userId);

    if (!serialQueue_) {
        HILOG_ERROR("serialQueue is nullptr");
        return;
    }

    serialQueue_->ScheduleTask(0, [userId]() {
        FormInfoMgr::GetInstance().ReloadFormInfos(userId);
    });
}
}  // namespace AppExecFwk
}  // namespace OHOS
