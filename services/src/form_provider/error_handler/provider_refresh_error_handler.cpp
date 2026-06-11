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

#include "ams_mgr/form_ams_helper.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_provider/form_provider_mgr.h"

namespace OHOS {
namespace AppExecFwk {

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

    if (policy.GetOriginalConnection() == nullptr) {
        HILOG_ERROR("No connection in retryPolicy, abort retry for formId %{public}" PRId64, formId);
        retryPolicyMap_.erase(formId);
        return false;
    }

    if (policy.NeedRetry()) {
        HILOG_INFO("Scheduling retry from HandleSendRequestFailed, formId %{public}" PRId64, formId);
        sptr<FormAbilityConnection> connection = policy.GetOriginalConnection();
        policy.IncrementRetryCount();
        policy.SetDisconnectFailed(false);
        policy.SetSendRequestFailed(false);
        policy.SetOriginalConnection(nullptr);
        ScheduleRetry(formId, policy,
            [formId, connection, weakHandler = wptr<FormProviderRefreshErrorHandler>(this)]() {
                sptr<FormProviderRefreshErrorHandler> handler = weakHandler.promote();
                if (handler == nullptr) {
                    HILOG_INFO("Handler destroyed, skip retry for formId %{public}" PRId64, formId);
                    return;
                }
                handler->ExecuteRefreshRetry(formId, connection);
            });
        return false;
    }

    HILOG_WARN("Retry limit reached formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(formId);
    return false;
}

bool FormProviderRefreshErrorHandler::HandleDisconnectError(int64_t formId,
    const sptr<FormAbilityConnection> &connection)
{
    ConnectState state = connection->GetConnectState();
    if (state != ConnectState::CONNECTED) {
        HILOG_WARN("state not connected, not handled");
        return false;
    }

    std::lock_guard<std::mutex> lock(retryPolicyMutex_);
    auto &policy = EnsureRetryPolicy(formId);
    policy.SetOriginalConnection(connection);
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
        policy.SetOriginalConnection(nullptr);
        ScheduleRetry(formId, policy,
            [formId, connection, weakHandler = wptr<FormProviderRefreshErrorHandler>(this)]() {
                sptr<FormProviderRefreshErrorHandler> handler = weakHandler.promote();
                if (handler == nullptr) {
                    HILOG_INFO("Handler destroyed, skip retry for formId %{public}" PRId64, formId);
                    return;
                }
                handler->ExecuteRefreshRetry(formId, connection);
            });
        return true;
    }

    HILOG_WARN("Retry limit reached on disconnect, formId %{public}" PRId64, formId);
    retryPolicyMap_.erase(formId);
    return true;
}

void FormProviderRefreshErrorHandler::ExecuteRefreshRetry(
    int64_t formId, sptr<FormAbilityConnection> originalConnection)
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

    sptr<FormAbilityConnection> clonedConnection = originalConnection->Clone();
    if (clonedConnection == nullptr) {
        HILOG_ERROR("Clone connection failed, abort retry for formId %{public}" PRId64, formId);
        std::lock_guard<std::mutex> lock(retryPolicyMutex_);
        retryPolicyMap_.erase(formId);
        return;
    }
    
    Want connectWant = clonedConnection->CreateConnectWant();
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(
        connectWant, clonedConnection, clonedConnection->GetUserId());
    if (errorCode != ERR_OK) {
        HILOG_ERROR("Retry connect failed, errorCode:%{public}d", errorCode);
        std::lock_guard<std::mutex> lock(retryPolicyMutex_);
        retryPolicyMap_.erase(formId);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS