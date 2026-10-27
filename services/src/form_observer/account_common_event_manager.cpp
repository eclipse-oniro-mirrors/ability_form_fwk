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

#include "form_observer/account_common_event_manager.h"

#include <common_event_manager.h>
#include <common_event_support.h>
#include <common_event_subscriber.h>
#include <unistd.h>

#include "common/util/form_task_common.h"
#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_queue.h"
#include "data_center/form_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t RETRY_SUBSCRIBER_MAX = 3;
constexpr int32_t RETRY_SUBSCRIBER_DELAY_MS = 500;
constexpr const char *ACCOUNT_LOGIN_ACTION = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";
constexpr const char *ACCOUNT_LOGOUT_ACTION = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";
constexpr const char *MANAGE_LOCAL_ACCOUNTS_PERMISSION = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
}

AccountCommonEventManager::AccountCommonEventManager()
{
    isRegistered_.store(false);
    retryCount_.store(0);
}

AccountCommonEventManager::~AccountCommonEventManager()
{
    isShutdown_.store(true);
    UnregisterAccountCallback();
}

void AccountCommonEventManager::RegisterAccountCallback()
{
    HILOG_DEBUG("Register account callback begin, post to queue");
    auto task = []() {
        AccountCommonEventManager::GetInstance().RegisterAccountCallbackInternal();
    };
    FormMgrQueue::GetInstance().ScheduleTask(0, task);
}

void AccountCommonEventManager::RegisterAccountCallbackInternal()
{
    if (isShutdown_.load()) {
        return;
    }
    if (!FormDataMgr::GetInstance().HasAccountConditionForm()) {
        HILOG_WARN("no need to register RegisterAccountCallback");
        return;
    }

    if (isRegistered_.load()) {
        HILOG_WARN("AccountCommonEventObserver already registered");
        return;
    }

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ACCOUNT_LOGIN_ACTION);
    matchingSkills.AddEvent(ACCOUNT_LOGOUT_ACTION);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    // Permission filter: only receive broadcasts from account service
    subscribeInfo.SetPermission(MANAGE_LOCAL_ACCOUNTS_PERMISSION);

    observer_ = std::make_shared<AccountCommonEventObserver>(subscribeInfo);
    bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(observer_);
    if (subscribeResult) {
        HILOG_INFO("Register AccountCommonEventObserver successful");
        isRegistered_.store(true);
        retryCount_.store(0);
        return;
    }

    HILOG_ERROR("Register AccountCommonEventObserver failed, retryCount:%{public}d", retryCount_.load());
    retryCount_.fetch_add(1);
    if (retryCount_.load() >= RETRY_SUBSCRIBER_MAX) {
        HILOG_ERROR("Register AccountCommonEventObserver failed %{public}d times, give up", RETRY_SUBSCRIBER_MAX);
        observer_ = nullptr;
        return;
    }
    PostRetryRegister();
}

void AccountCommonEventManager::UnregisterAccountCallback()
{
    HILOG_DEBUG("Unregister account callback begin, post to queue");
    auto task = []() {
        AccountCommonEventManager::GetInstance().UnregisterAccountCallbackInternal();
    };
    FormMgrQueue::GetInstance().ScheduleTask(0, task);
}

void AccountCommonEventManager::UnregisterAccountCallbackInternal()
{
    HILOG_INFO("Unregister account callback begin");
    if (isRegistered_.load() && observer_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(observer_);
        observer_ = nullptr;
    }
    if (!isRegistered_.load()) {
        HILOG_WARN("AccountCommonEventObserver not registered");
        return;
    }
    isRegistered_.store(false);
    retryCount_.store(0);
    HILOG_INFO("Unregister account callback end");
}

void AccountCommonEventManager::PostRetryRegister()
{
    HILOG_DEBUG("Post retry register account callback");
    auto retryTask = []() {
        AccountCommonEventManager::GetInstance().RegisterAccountCallbackInternal();
    };
    FormMgrQueue::GetInstance().ScheduleTask(RETRY_SUBSCRIBER_DELAY_MS, retryTask);
}
} // namespace AppExecFwk
} // namespace OHOS
