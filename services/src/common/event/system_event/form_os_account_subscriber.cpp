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

#include "common/event/system_event/form_os_account_subscriber.h"

#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_queue.h"
#include "data_center/form_info/form_info_mgr.h"
#include "common/util/form_task_common.h"

namespace OHOS {
namespace AppExecFwk {
void FormOsAccountSubscriber::OnStateChanged(const AccountSA::OsAccountStateData &data)
{
    if (data.state != AccountSA::OsAccountState::CREATED) {
        return;
    }
    int32_t userId = data.toId;
    if (userId < 0) {
        HILOG_WARN("invalid os account userId:%{public}d", userId);
        return;
    }
    HILOG_INFO("os account created, userId:%{public}d, schedule reload", userId);
    // Callback runs on a binder thread: only enqueue, never execute reload inline.
    FormMgrQueue::GetInstance().ScheduleTask(0, [userId]() {
        FormInfoMgr::GetInstance().ReloadFormInfos(userId);
    }, Common::TaskQos::QOS_DEADLINE_REQUEST);
}
} // namespace AppExecFwk
} // namespace OHOS
