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

#ifndef OHOS_FORM_FWK_RETRY_POLICY_H
#define OHOS_FORM_FWK_RETRY_POLICY_H

#include <cstdint>
#include "refbase.h"

namespace OHOS {
namespace AppExecFwk {

// Forward declaration to avoid circular dependency
class FormAbilityConnection;

constexpr int32_t EXPONENTIAL_MULTIPLIER = 2;

enum class RetryStrategyType {
    IMMEDIATE,
    FIXED_INTERVAL,
    LINEAR,
    EXPONENTIAL
};

struct RetryPolicyConfig {
    int32_t maxRetryCount = 3;
    RetryStrategyType strategyType = RetryStrategyType::LINEAR;
    int32_t baseDelayMs = 500;
    int32_t maxDelayMs = 1500;
};

class RetryPolicy {
public:
    RetryPolicy() = default;
    explicit RetryPolicy(const RetryPolicyConfig &config);

    bool NeedRetry() const;
    int32_t GetRetryCount() const;
    void IncrementRetryCount();
    void Reset();
    bool IsRetryLimitReached() const;
    /**
     * @brief Calculate delay before next retry.
     *
     * Called AFTER IncrementRetryCount(), so retryCount_ is 1-based:
     *   retryCount_=1 means 1st retry, retryCount_=2 means 2nd retry, etc.
     *
     * Default config (LINEAR, base=500ms, max=1500ms, maxRetry=3):
     *   retry 1 ->  500ms
     *   retry 2 -> 1000ms
     *   retry 3 -> 1500ms
     *
     * @return Delay in milliseconds.
     */
    int32_t CalculateNextDelay() const;

    bool IsSendRequestFailed() const;
    void SetSendRequestFailed(bool failed);
    bool IsDisconnectFailed() const;
    void SetDisconnectFailed(bool failed);

    sptr<FormAbilityConnection> GetOriginalConnection() const;
    void SetOriginalConnection(const sptr<FormAbilityConnection> &connection);

private:
    bool sendRequestFailed_ = false;
    bool disconnectFailed_ = false;
    RetryPolicyConfig config_;
    int32_t retryCount_ = 0;
    sptr<FormAbilityConnection> originalConnection_;
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_RETRY_POLICY_H