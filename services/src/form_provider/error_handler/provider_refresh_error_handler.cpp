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

#include "form_provider/error_handler/provider_refresh_error_handler.h"

#include <cinttypes>
#include <memory>

#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_provider/form_provider_mgr.h"

namespace OHOS {
namespace AppExecFwk {

std::shared_ptr<FormProviderRefreshErrorHandler> FormProviderRefreshErrorHandler::Create()
{
    return std::shared_ptr<FormProviderRefreshErrorHandler>(new FormProviderRefreshErrorHandler());
}

bool FormProviderRefreshErrorHandler::HandleConnectError(
    int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want)
{
    if (remoteObject == nullptr || remoteObject->IsObjectDead()) {
        HILOG_WARN("ConnectServiceAbility failed, remote dead, formId %{public}" PRId64, formId);
    }
    return false;
}

bool FormProviderRefreshErrorHandler::HandleSendRequestFailed(
    int64_t formId, int errorCode, const Want &want)
{
    if (!IsRemoteDead(errorCode)) {
        HILOG_WARN("Non-remote-dead error %{public}d, caller will RemoveConnection", errorCode);
        return false;
    }

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto &policy = EnsureRetryPolicy(formId);
    policy.SetSendRequestFailed(true);

    if (!policy.IsDisconnectFailed()) {
        HILOG_INFO("Waiting for connection disconnect callback, formId %{public}" PRId64, formId);
        return true;
    }

    if (policy.NeedRetry()) {
        HILOG_INFO("Scheduling retry from HandleSendRequestFailed, formId %{public}" PRId64, formId);
        policy.IncrementRetryCount();
        policy.SetDisconnectFailed(false);
        policy.SetSendRequestFailed(false);
        ScheduleRetry(formId, want, policy,
            [formId, want, weakPtr = weak_from_this()]() {
                auto handler = weakPtr.lock();
                if (handler == nullptr) {
                    HILOG_INFO("Handler destroyed, skip retry for formId %{public}" PRId64, formId);
                    return;
                }
                handler->ExecuteRefreshRetry(formId, want);
            });
        return false;
    }

    HILOG_WARN("Retry limit reached formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(formId);
    return false;
}

bool FormProviderRefreshErrorHandler::HandleDisconnectError(int64_t formId, const sptr<IRemoteObject> &remoteObject,
    const Want &want, ConnectState state)
{
    if (state != ConnectState::CONNECTED) {
        HILOG_WARN("state not connected, not handled");
        return false;
    }

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto &policy = EnsureRetryPolicy(formId);
    policy.SetDisconnectFailed(true);

    if (!policy.IsSendRequestFailed()) {
        HILOG_WARN("Disconnect without prior SendRequest failure, not handled");
        return false;
    }

    if (policy.NeedRetry()) {
        HILOG_INFO("Dual-signal confirmed, scheduling retry for formId %{public}" PRId64, formId);
        policy.IncrementRetryCount();
        policy.SetDisconnectFailed(false);
        policy.SetSendRequestFailed(false);
        ScheduleRetry(formId, want, policy,
            [formId, want, weakPtr = weak_from_this()]() {
                auto handler = weakPtr.lock();
                if (handler == nullptr) {
                    HILOG_INFO("Handler destroyed, skip retry for formId %{public}" PRId64, formId);
                    return;
                }
                handler->ExecuteRefreshRetry(formId, want);
            });
        return true;
    }

    HILOG_WARN("Retry limit reached on disconnect, formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(formId);
    return true;
}

void FormProviderRefreshErrorHandler::ExecuteRefreshRetry(
    int64_t formId, const Want &want)
{
    FormRecord record;
    bool success = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    {
        std::lock_guard<std::mutex> lock(retryPolicyMutex_);
        if (retryPolicyMap_.find(formId) == retryPolicyMap_.end()) {
            HILOG_INFO("Retry policy already removed, skip retry for formId %{public}" PRId64, formId);
            return;
        }
        if (!success) {
            retryPolicyMap_.erase(formId);
            HILOG_WARN("FormRecord not found, abort retry for formId %{public}" PRId64, formId);
            return;
        }
    }

    FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
}

}  // namespace AppExecFwk
}  // namespace OHOS