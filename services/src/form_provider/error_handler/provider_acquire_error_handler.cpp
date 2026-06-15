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

#include "form_provider/error_handler/provider_acquire_error_handler.h"

#include "common/util/form_task_common.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_event_report_define.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {

TaskType FormProviderAcquireErrorHandler::GetRetryTaskType() const
{
    return TaskType::ACQUIRE_RETRY_TASK;
}

void FormProviderAcquireErrorHandler::OnPrepareRetryConnect(sptr<FormAbilityConnection> &connection)
{
    // Acquire-only: mark CONNECTING to complete the state machine before AMS connect.
    if (connection != nullptr) {
        connection->SetConnectState(ConnectState::CONNECTING);
    }
}

void FormProviderAcquireErrorHandler::OnRetryLimitReached(int64_t formId)
{
    // Align with ReAcquireProviderFormInfoAsync exhaustion: report HiSys failed event, no host push.
    HILOG_WARN("Acquire retry limit reached, formId %{public}" PRId64, formId);
    FormEventReport::SendFormFailedEvent(FormEventName::CONNECT_FORM_ABILITY_FAILED, formId,
        "", "", static_cast<int32_t>(ConnectFormAbilityErrorType::UPDATE_FORM_FAILED),
        ERR_APPEXECFWK_CONNECT_PROVIDER_TIMEOUT);
}

}  // namespace AppExecFwk
}  // namespace OHOS
