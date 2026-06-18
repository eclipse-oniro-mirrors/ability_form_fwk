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

#include "form_provider/error_handler/provider_connection_error_handler.h"

#include <cinttypes>
#include <utility>

#include "ams_mgr/form_ams_helper.h"
#include "common/util/form_task_common.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_queue.h"

namespace OHOS {
namespace AppExecFwk {

bool FormProviderConnectionErrorHandler::IsRemoteDead(int errorCode)
{
    return errorCode == IPC_ERR_DEAD_OBJECT || errorCode == IPC_ERR_SERVICE_DIED;
}

RetryPolicy FormProviderConnectionErrorHandler::GetDefaultRetryPolicy() const
{
    return RetryPolicy();
}

RetryPolicy &FormProviderConnectionErrorHandler::EnsureRetryPolicyLocked(int64_t formId)
{
    auto it = retryPolicyMap_.find(formId);
    if (it == retryPolicyMap_.end()) {
        it = retryPolicyMap_.emplace(formId, GetDefaultRetryPolicy()).first;
        HILOG_INFO("Created retry policy for formId %{public}" PRId64, formId);
    }
    return it->second;
}

void FormProviderConnectionErrorHandler::CancelPendingTasks(int64_t formId)
{
    FormMgrQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId));
    CancelSignalTimeout(formId);
}

void FormProviderConnectionErrorHandler::RemoveRetryPolicy(int64_t formId)
{
    CancelPendingTasks(formId);
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    retryPolicyMap_.erase(formId);
    HILOG_DEBUG("Removed retry policy for formId %{public}" PRId64, formId);
}

void FormProviderConnectionErrorHandler::CancelSignalTimeout(int64_t formId)
{
    FormMgrQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(TaskType::REFRESH_RETRY_TIMEOUT_TASK), formId));
}

void FormProviderConnectionErrorHandler::StartSignalTimeout(int64_t formId)
{
    FormMgrQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(static_cast<int64_t>(TaskType::REFRESH_RETRY_TIMEOUT_TASK), formId),
        RETRY_SIGNAL_TIMEOUT_MS,
        [formId, weakHandler = wptr<FormProviderConnectionErrorHandler>(this)]() {
            sptr<FormProviderConnectionErrorHandler> handler = weakHandler.promote();
            if (handler == nullptr) {
                return;
            }
            handler->OnSignalTimeout(formId);
        });
}

void FormProviderConnectionErrorHandler::OnSignalTimeout(int64_t formId)
{
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto it = retryPolicyMap_.find(formId);
    if (it == retryPolicyMap_.end()) {
        HILOG_INFO("Signal timeout: policy already removed, formId %{public}" PRId64, formId);
        return;
    }
    RetryPolicy &policy = it->second;
    // Clean up only if exactly one signal arrived (flags differ). If both are set, a retry
    // is in progress; if neither, the policy is idle. The common trigger: FormExtension
    // exits after handling the request, causing a disconnect without a SendRequest failure.
    if (policy.IsSendRequestFailed() == policy.IsDisconnectFailed()) {
        HILOG_INFO("Signal timeout: both signals match (resolved or idle), formId %{public}" PRId64, formId);
        return;
    }
    HILOG_WARN("Dual-signal timeout, cleaning up partial state for formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(it);
}

void FormProviderConnectionErrorHandler::ScheduleRetry(int64_t formId,
    const RetryPolicy &policy, std::function<void()> retryFunc)
{
    int32_t delayMs = policy.CalculateNextDelay();
    HILOG_INFO("Scheduling retry for formId %{public}" PRId64 ", delay=%{public}dms", formId, delayMs);
    FormMgrQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId),
        delayMs, retryFunc);
}

bool FormProviderConnectionErrorHandler::HandleSendRequestFailed(
    int64_t formId, int errorCode, const Want &want)
{
    if (!IsRemoteDead(errorCode)) {
        HILOG_WARN("Non-remote-dead error %{public}d, caller will RemoveConnection", errorCode);
        return false;
    }

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto &policy = EnsureRetryPolicyLocked(formId);
    policy.SetSendRequestFailed(true);

    if (!policy.IsDisconnectFailed()) {
        HILOG_INFO("Waiting for connection disconnect callback, formId %{public}" PRId64, formId);
        StartSignalTimeout(formId); // Fallback if disconnect callback never arrives
        return true;
    }

    if (policy.GetOriginalConnection() == nullptr) {
        HILOG_ERROR("No connection in retryPolicy, abort retry for formId %{public}" PRId64, formId);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        return false;
    }

    if (policy.NeedRetry()) {
        HILOG_INFO("Scheduling retry from HandleSendRequestFailed, formId %{public}" PRId64, formId);
        sptr<FormAbilityConnection> connection = policy.GetOriginalConnection();
        ScheduleRetryWithReset(formId, policy, connection);
        return true;
    }

    HILOG_WARN("Retry limit reached formId %{public}" PRId64, formId);
    OnRetryLimitReached(formId);
    CancelPendingTasks(formId);
    retryPolicyMap_.erase(formId);
    return false;
}

bool FormProviderConnectionErrorHandler::HandleDisconnectError(int64_t formId,
    const sptr<FormAbilityConnection> &connection)
{
    if (connection == nullptr) {
        HILOG_ERROR("null connection, abort HandleDisconnectError for formId %{public}" PRId64, formId);
        return false;
    }
    ConnectState state = connection->GetConnectState();
    if (state != ConnectState::CONNECTED) {
        HILOG_WARN("state not connected, not handled");
        return false;
    }

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto &policy = EnsureRetryPolicyLocked(formId);
    policy.SetOriginalConnection(connection);
    policy.SetDisconnectFailed(true);

    if (!policy.IsSendRequestFailed()) {
        HILOG_WARN("Disconnect without prior SendRequest failure, not handled");
        StartSignalTimeout(formId); // Fallback if no SendRequest failure follows
        return false;
    }

    if (policy.NeedRetry()) {
        HILOG_INFO("Dual-signal confirmed, scheduling retry for formId %{public}" PRId64, formId);
        ScheduleRetryWithReset(formId, policy, connection);
        return true;
    }

    HILOG_WARN("Retry limit reached on disconnect, formId %{public}" PRId64, formId);
    OnRetryLimitReached(formId);
    CancelPendingTasks(formId);
    retryPolicyMap_.erase(formId);
    return true;
}

void FormProviderConnectionErrorHandler::ScheduleRetryWithReset(int64_t formId, RetryPolicy &policy,
    const sptr<FormAbilityConnection> &connection)
{
    CancelSignalTimeout(formId); // dual-signal resolved, no need for the fallback timeout
    policy.IncrementRetryCount();
    policy.SetDisconnectFailed(false);
    policy.SetSendRequestFailed(false);
    policy.SetOriginalConnection(nullptr);

    ScheduleRetry(formId, policy,
        [formId, connection, weakHandler = wptr<FormProviderConnectionErrorHandler>(this)]() {
            sptr<FormProviderConnectionErrorHandler> handler = weakHandler.promote();
            if (handler == nullptr) {
                HILOG_INFO("Handler destroyed, skip retry for formId %{public}" PRId64, formId);
                return;
            }
            handler->ExecuteRetry(formId, connection);
        });
}

void FormProviderConnectionErrorHandler::ExecuteRetry(
    int64_t formId, const sptr<FormAbilityConnection> &originalConnection)
{
    HILOG_INFO("Execute retry, formId %{public}" PRId64, formId);
    bool formExist = FormDataMgr::GetInstance().HasFormRecord(formId);

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    if (retryPolicyMap_.find(formId) == retryPolicyMap_.end()) {
        HILOG_INFO("Retry policy already removed, skip retry for formId %{public}" PRId64, formId);
        return;
    }
    if (!formExist) {
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        HILOG_WARN("FormRecord not found, abort retry for formId %{public}" PRId64, formId);
        return;
    }
    if (originalConnection == nullptr) {
        HILOG_ERROR("null originalConnection, abort retry for formId %{public}" PRId64, formId);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        return;
    }

    sptr<FormAbilityConnection> retryConnection = originalConnection->CreateRetryConnection();
    if (retryConnection == nullptr) {
        HILOG_ERROR("Create retry connection failed, abort retry for formId %{public}" PRId64, formId);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        return;
    }
    retryConnection->SetConnectState(ConnectState::CONNECTING);

    Want connectWant = retryConnection->CreateConnectWant();
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(
        connectWant, retryConnection, retryConnection->GetUserId());
    if (errorCode != ERR_OK) {
        HILOG_ERROR("Retry connect failed, errorCode:%{public}d", errorCode);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS
