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

#include "refbase.h"
#include "common/connection/form_ability_connection.h"
#include "common/retry_policy/retry_policy.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = AAFwk::Want;

/**
 * @class FormProviderConnectionErrorHandler
 * Base class for handling provider connection errors with retry policy management.
 * Provides dual-signal confirmed delayed retry mechanism for IPC errors.
 */
class FormProviderConnectionErrorHandler : public RefBase {
public:
    virtual ~FormProviderConnectionErrorHandler() = default;

    /**
     * @brief Check if the error code indicates remote object is dead.
     * @param errorCode IPC error code.
     * @return true if remote is dead (32 or 29189), false otherwise.
     */
    static bool IsRemoteDead(int errorCode);

    /**
     * @brief Handle send request failed error (first signal in dual-signal mechanism).
     *        Marks sendRequestFailed signal and checks dual-signal condition.
     * @param formId Form ID.
     * @param errorCode IPC error code.
     * @param want Want parameter for retry.
     * @return true if waiting for disconnect callback (first signal only),
     *         false if non-dead-error/dual-signal-confirmed/retry-limit-reached.
     */
    virtual bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want) = 0;

    /**
     * @brief Handle disconnect error (second signal in dual-signal mechanism).
     *        Checks dual-signal condition and triggers retry if confirmed.
     * @param formId Form ID.
     * @param connection Form ability connection object.
     * @return true if dual-signal confirmed and retry scheduled, false otherwise.
     */
    virtual bool HandleDisconnectError(int64_t formId, const sptr<FormAbilityConnection> &connection) = 0;

    /**
     * @brief Remove retry policy for specified form.
     * @param formId Form ID.
     */
    void RemoveRetryPolicy(int64_t formId);

protected:
    static constexpr int32_t IPC_ERR_DEAD_OBJECT = 32;
    static constexpr int32_t IPC_ERR_SERVICE_DIED = 29189;

    std::unordered_map<int64_t, RetryPolicy> retryPolicyMap_;
    std::mutex retryPolicyMutex_;

    /**
     * @brief Schedule retry task with exponential backoff delay.
     *        Calculates next delay based on retry policy and schedules retry.
     * @param formId Form ID.
     * @param policy Retry policy configuration.
     * @param retryFunc Retry function to execute.
     */
    virtual void ScheduleRetry(int64_t formId, const RetryPolicy &policy,
        std::function<void()> retryFunc);

    /**
     * @brief Get default retry policy configuration.
     * @return Default retry policy with maxRetryCount=3, strategyType=LINEAR, baseDelayMs=500, maxDelayMs=1500.
     */
    RetryPolicy GetDefaultRetryPolicy() const;

    /**
     * @brief Ensure retry policy exists for specified form (create default if absent).
     *        Must be called within lock_guard of retryPolicyMutex_.
     * @param formId Form ID.
     * @return Reference to retry policy in retryPolicyMap_.
     */
    RetryPolicy &EnsureRetryPolicy(int64_t formId);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H