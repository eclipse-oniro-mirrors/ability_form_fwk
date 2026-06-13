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

#include "common/util/form_task_common.h"
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

RetryPolicy &FormProviderConnectionErrorHandler::EnsureRetryPolicy(int64_t formId)
{
    auto it = retryPolicyMap_.find(formId);
    if (it == retryPolicyMap_.end()) {
        it = retryPolicyMap_.emplace(formId, GetDefaultRetryPolicy()).first;
        HILOG_INFO("Created retry policy for formId %{public}" PRId64, formId);
    }
    return it->second;
}

void FormProviderConnectionErrorHandler::RemoveRetryPolicy(int64_t formId)
{
    FormMgrQueue::GetInstance().CancelDelayTask(
        std::make_pair(static_cast<int64_t>(TaskType::REFRESH_RETRY_TASK), formId));
    CancelSignalTimeout(formId);
    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    retryPolicyMap_.erase(formId);
    HILOG_INFO("Removed retry policy for formId %{public}" PRId64, formId);
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
        return; // already resolved or removed
    }
    RetryPolicy &policy = it->second;
    // Stuck half-signal = exactly one of the two signals arrived. Both-set is transient
    // (retry resets flags to false); neither means idle -> in those cases do nothing.
    //
    // FMS and AMS are co-located in the foundation process, so the disconnect callback is
    // delivered in-process and reliably resolves the sendRequest-first (S1) state within
    // milliseconds; this timeout therefore only ever fires for S2 (disconnect without a
    // pending sendRequest, e.g. normal FormExtension exit), cleaning up the lingering policy.
    if (policy.IsSendRequestFailed() == policy.IsDisconnectFailed()) {
        return;
    }
    HILOG_WARN("Dual-signal timeout, cleaning up stuck half-signal for formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(it);
}

void FormProviderConnectionErrorHandler::ScheduleRetry(int64_t formId,
    const RetryPolicy &policy, std::function<void()> retryFunc)
{
    int32_t delayMs = policy.CalculateNextDelay();
    HILOG_INFO("Scheduling retry for formId %{public}" PRId64 ", delay=%{public}dms", formId, delayMs);
    FormMgrQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(static_cast<int64_t>(TaskType::REFRESH_RETRY_TASK), formId),
        delayMs, retryFunc);
}

}  // namespace AppExecFwk
}  // namespace OHOS