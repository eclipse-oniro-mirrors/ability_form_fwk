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

#include "form_observer/account_common_event_observer.h"

#include <common_event_data.h>
#include <common_event_support.h>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr/form_data_adapter.h"
#include "form_mgr/form_mgr_queue.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *ACCOUNT_LOGIN_ACTION = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";
constexpr const char *ACCOUNT_LOGOUT_ACTION = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";
constexpr const char *KEY_USER_ID = "userId";
constexpr const int INVALID_USER_ID = -1;
}

void AccountCommonEventObserver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = want.GetAction();
    HILOG_INFO("AccountCommonEvent receive action:%{public}s", action.c_str());

    // Filter non-account events
    if (action != ACCOUNT_LOGIN_ACTION && action != ACCOUNT_LOGOUT_ACTION) {
        HILOG_WARN("Ignore non-account event: %{public}s", action.c_str());
        return;
    }

    // Extract userId from event data code
    int32_t userId = want.GetParams().GetIntParam(KEY_USER_ID, INVALID_USER_ID);
    if (userId < 0) {
        HILOG_WARN("Invalid userId:%{public}d, skip refresh", userId);
        return;
    }
    HILOG_ERROR("zzz refresh 1");
    HILOG_INFO("Account event action:%{public}s userId:%{public}d", action.c_str(), userId);
    // Dispatch to FMS main thread via queue
    auto task = [userId]() {
        FormDataAdapter::GetInstance().UpdateFormByCondition(Constants::CONDITION_ACCOUNT, userId);
    };
    FormMgrQueue::GetInstance().ScheduleTask(0, task);
}
} // namespace AppExecFwk
} // namespace OHOS
