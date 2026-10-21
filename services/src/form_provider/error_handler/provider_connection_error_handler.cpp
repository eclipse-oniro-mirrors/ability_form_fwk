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
#include "form_provider/form_provider_queue.h"

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
    // Retry, signal-timeout and callback-timeout tasks share the single key slot
    // (GetRetryTaskType(), formId); one cancel removes whichever is pending.
    FormProviderQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId));
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
    FormProviderQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId));
}

void FormProviderConnectionErrorHandler::StartSignalTimeout(int64_t formId)
{
    FormProviderQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId),
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
    RequestStage stage = policy.GetStage();
    if (stage == RequestStage::WAITING_DISCONNECT_CONFIRM || stage == RequestStage::WAITING_SEND_RESULT) {
        HILOG_WARN("%{public}s: Signal timeout, cleaning up partial state for formId %{public}" PRId64,
            GetScenarioName(), formId);
        retryPolicyMap_.erase(it);
    }
}

void FormProviderConnectionErrorHandler::StartCallbackPending(int64_t formId, int32_t connectId)
{
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    CancelCallbackTimeout(formId);
    CancelSignalTimeout(formId);
    auto &policy = EnsureRetryPolicyLocked(formId);
    policy.SetStage(RequestStage::WAITING_CALLBACK);
    policy.SetCallbackConnectId(connectId);
    StartCallbackTimeout(formId, connectId);
}

void FormProviderConnectionErrorHandler::StartCallbackTimeout(int64_t formId, int32_t connectId)
{
    FormProviderQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId),
        CALLBACK_TIMEOUT_MS,
        [formId, connectId, weakHandler = wptr<FormProviderConnectionErrorHandler>(this)]() {
            sptr<FormProviderConnectionErrorHandler> handler = weakHandler.promote();
            if (handler == nullptr) {
                return;
            }
            handler->OnCallbackTimeout(formId, connectId);
        });
}

void FormProviderConnectionErrorHandler::CancelCallbackTimeout(int64_t formId)
{
    FormProviderQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(GetRetryTaskType()), formId));
}

void FormProviderConnectionErrorHandler::OnCallbackTimeout(int64_t formId, int32_t expectedConnectId)
{
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto it = retryPolicyMap_.find(formId);
    if (it == retryPolicyMap_.end()) {
        HILOG_INFO("Policy already removed, formId %{public}" PRId64, formId);
        return;
    }
    RetryPolicy &policy = it->second;
    if (policy.GetStage() != RequestStage::WAITING_CALLBACK) {
        HILOG_INFO("Ignore non-waiting stage %{public}d, formId %{public}" PRId64,
            static_cast<int32_t>(policy.GetStage()), formId);
        return;
    }
    if (policy.GetCallbackConnectId() != expectedConnectId) {
        HILOG_INFO("Ignore stale connectId %{public}d, formId %{public}" PRId64,
            expectedConnectId, formId);
        return;
    }
    HILOG_INFO("Callback wait timeout, no retry, formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(it);
}

void FormProviderConnectionErrorHandler::OnCallbackArrived(int64_t formId, int32_t connectId)
{
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto it = retryPolicyMap_.find(formId);
    if (it == retryPolicyMap_.end()) {
        HILOG_INFO("Callback arrival without policy, formId %{public}" PRId64 ", connectId %{public}d",
            formId, connectId);
        return;
    }
    RetryPolicy &policy = it->second;
    if (policy.GetStage() != RequestStage::WAITING_CALLBACK) {
        HILOG_INFO("Callback arrival ignored, stage %{public}d, formId %{public}" PRId64 ", connectId %{public}d",
            static_cast<int32_t>(policy.GetStage()), formId, connectId);
        return;
    }
    if (policy.GetCallbackConnectId() != connectId) {
        HILOG_INFO("Callback arrival ignored, stale connectId %{public}d, formId %{public}" PRId64,
            connectId, formId);
        return;
    }
    CancelCallbackTimeout(formId);
    CancelSignalTimeout(formId);
    policy.SetStage(RequestStage::CALLBACK_COMPLETED);
    HILOG_INFO("stage=WAITING_CALLBACK->CALLBACK_COMPLETED, formId %{public}" PRId64, formId);
}

void FormProviderConnectionErrorHandler::ScheduleRetry(int64_t formId,
    const RetryPolicy &policy, std::function<void()> retryFunc)
{
    int32_t delayMs = policy.CalculateNextDelay();
    HILOG_INFO("%{public}s: Scheduling retry for formId %{public}" PRId64 ", delay=%{public}dms",
        GetScenarioName(), formId, delayMs);
    FormProviderQueue::GetInstance().ScheduleDelayTask(
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
    if (policy.GetStage() == RequestStage::WAITING_SEND_RESULT) {
        if (policy.GetOriginalConnection() == nullptr) {
            HILOG_ERROR("%{public}s: No connection in retryPolicy, abort retry for formId %{public}" PRId64,
                GetScenarioName(), formId);
            CancelPendingTasks(formId);
            retryPolicyMap_.erase(formId);
            return false;
        }
        if (policy.IsRetryLimitReached()) {
            HILOG_WARN("%{public}s: Retry limit reached formId %{public}" PRId64, GetScenarioName(), formId);
            CancelPendingTasks(formId);
            retryPolicyMap_.erase(formId);
            OnRetryLimitReached(formId);
            return false;
        }
        HILOG_INFO("%{public}s: Scheduling retry from HandleSendRequestFailed, formId %{public}" PRId64,
            GetScenarioName(), formId);
        ScheduleRetryWithReset(formId, policy, policy.GetOriginalConnection());
        return true;
    }
    HILOG_INFO("%{public}s: Send request failed, waiting for disconnect confirmation, formId %{public}" PRId64,
        GetScenarioName(), formId);
    policy.SetStage(RequestStage::WAITING_DISCONNECT_CONFIRM);
    StartSignalTimeout(formId);
    return true;
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

    switch (policy.GetStage()) {
        case RequestStage::WAITING_CALLBACK:
            return HandleDisconnectOnWaitingCallback(formId, policy, connection);
        case RequestStage::CALLBACK_COMPLETED:
            HILOG_INFO("Callback already completed, erase policy on disconnect, formId %{public}" PRId64, formId);
            CancelPendingTasks(formId);
            retryPolicyMap_.erase(formId);
            return true;
        case RequestStage::WAITING_DISCONNECT_CONFIRM:
            return HandleDisconnectOnWaitingConfirm(formId, policy, connection);
        case RequestStage::IDLE:
        case RequestStage::WAITING_SEND_RESULT:
            // The disconnect may precede the SendRequest failure (reverse order).
            HILOG_WARN("%{public}s: Disconnect arrived before send request failure, not handled, "
                "formId %{public}" PRId64, GetScenarioName(), formId);
            policy.SetStage(RequestStage::WAITING_SEND_RESULT);
            StartSignalTimeout(formId);
            return false;
        default:
            HILOG_ERROR("Unexpected stage %{public}d, formId %{public}" PRId64,
                static_cast<int32_t>(policy.GetStage()), formId);
            return false;
    }
}

bool FormProviderConnectionErrorHandler::HandleDisconnectOnWaitingCallback(int64_t formId, RetryPolicy &policy,
    const sptr<FormAbilityConnection> &connection)
{
    CancelCallbackTimeout(formId);
    if (CheckRetryLimitReached(formId, policy)) {
        return true;
    }
    HILOG_INFO("Callback lost on disconnect, scheduling retry for formId %{public}" PRId64, formId);
    ScheduleRetryWithReset(formId, policy, connection);
    return true;
}

bool FormProviderConnectionErrorHandler::HandleDisconnectOnWaitingConfirm(int64_t formId, RetryPolicy &policy,
    const sptr<FormAbilityConnection> &connection)
{
    if (CheckRetryLimitReached(formId, policy)) {
        return true;
    }
    HILOG_INFO("%{public}s: Send request failure and disconnect both confirmed, scheduling retry, "
        "formId %{public}" PRId64, GetScenarioName(), formId);
    ScheduleRetryWithReset(formId, policy, connection);
    return true;
}

bool FormProviderConnectionErrorHandler::CheckRetryLimitReached(int64_t formId, RetryPolicy &policy)
{
    if (!policy.IsRetryLimitReached()) {
        return false;
    }
    HILOG_WARN("%{public}s: Retry limit reached on disconnect, formId %{public}" PRId64, GetScenarioName(), formId);
    CancelPendingTasks(formId);
    retryPolicyMap_.erase(formId);
    OnRetryLimitReached(formId);
    return true;
}

void FormProviderConnectionErrorHandler::ScheduleRetryWithReset(int64_t formId, RetryPolicy &policy,
    const sptr<FormAbilityConnection> &connection)
{
    CancelSignalTimeout(formId);
    CancelCallbackTimeout(formId);
    policy.IncrementRetryCount();
    policy.SetStage(RequestStage::IDLE);
    policy.SetCallbackConnectId(0);
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

// Invariant: use only FormAbilityConnection base-class interfaces here. The original
// connection may be a refresh connection carrying a RECREATE task routed to this
// handler, so subclass-specific members must not be accessed.
void FormProviderConnectionErrorHandler::ExecuteRetry(
    int64_t formId, const sptr<FormAbilityConnection> &originalConnection)
{
    HILOG_INFO("%{public}s: Execute retry, formId %{public}" PRId64, GetScenarioName(), formId);
    bool formExist = FormDataMgr::GetInstance().HasFormRecord(formId);

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    if (retryPolicyMap_.find(formId) == retryPolicyMap_.end()) {
        HILOG_INFO("Retry policy already removed, skip retry for formId %{public}" PRId64, formId);
        return;
    }
    if (!formExist) {
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        HILOG_WARN("%{public}s: FormRecord not found, abort retry for formId %{public}" PRId64,
            GetScenarioName(), formId);
        return;
    }
    if (originalConnection == nullptr) {
        HILOG_ERROR("%{public}s: null originalConnection, abort retry for formId %{public}" PRId64,
            GetScenarioName(), formId);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        return;
    }

    sptr<FormAbilityConnection> retryConnection = originalConnection->CreateRetryConnection();
    if (retryConnection == nullptr) {
        HILOG_ERROR("%{public}s: Create retry connection failed, abort retry for formId %{public}" PRId64,
            GetScenarioName(), formId);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
        return;
    }
    retryConnection->SetConnectState(ConnectState::CONNECTING);

    Want connectWant = retryConnection->CreateConnectWant();
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(
        connectWant, retryConnection, retryConnection->GetUserId());
    if (errorCode != ERR_OK) {
        HILOG_ERROR("%{public}s: Retry connect failed, errorCode:%{public}d", GetScenarioName(), errorCode);
        CancelPendingTasks(formId);
        retryPolicyMap_.erase(formId);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS
