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

#ifndef OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H
#define OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H

#include <functional>
#include <mutex>
#include <unordered_map>

#include "common/connection/form_ability_connection.h"
#include "common/retry_policy/retry_policy.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = AAFwk::Want;

class FormProviderConnectionErrorHandler {
public:
    virtual ~FormProviderConnectionErrorHandler() = default;

    static bool IsRemoteDead(int errorCode);

    virtual bool HandleConnectError(int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want) = 0;

    virtual bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want) = 0;

    virtual bool HandleDisconnectError(int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want,
        ConnectState state) = 0;

    void RemoveRetryPolicy(int64_t formId);

    virtual void ScheduleRetry(int64_t formId, const Want &want, const RetryPolicy &policy,
        std::function<void()> retryFunc);

protected:
    static constexpr int32_t IPC_ERR_DEAD_OBJECT = 32;
    static constexpr int32_t IPC_ERR_SERVICE_DIED = 29189;

    std::unordered_map<int64_t, RetryPolicy> retryPolicyMap_;
    std::mutex retryPolicyMutex_;

    RetryPolicy GetDefaultRetryPolicy() const;
    // Ensure retry policy exists (create default if absent), must be called within lock_guard of retryPolicyMutex_
    RetryPolicy &EnsureRetryPolicy(int64_t formId);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H