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

#include "common/retry_policy/retry_policy.h"

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

RetryPolicy::RetryPolicy(const RetryPolicyConfig &config) : sendRequestFailed_(false), disconnectFailed_(false),
    config_(config), retryCount_(0) {}

bool RetryPolicy::NeedRetry() const
{
    return sendRequestFailed_ && disconnectFailed_ && retryCount_ < config_.maxRetryCount;
}

int32_t RetryPolicy::GetRetryCount() const
{
    return retryCount_;
}

void RetryPolicy::IncrementRetryCount()
{
    retryCount_++;
}

void RetryPolicy::Reset()
{
    retryCount_ = 0;
    sendRequestFailed_ = false;
    disconnectFailed_ = false;
}

bool RetryPolicy::IsRetryLimitReached() const
{
    return retryCount_ >= config_.maxRetryCount;
}

int32_t RetryPolicy::CalculateNextDelay() const
{
    if (config_.strategyType == RetryStrategyType::IMMEDIATE) {
        return 0;
    }
    if (config_.strategyType == RetryStrategyType::FIXED_INTERVAL) {
        return config_.baseDelayMs;
    }
    if (config_.strategyType == RetryStrategyType::LINEAR) {
        int32_t delay = config_.baseDelayMs * retryCount_;
        return delay > config_.maxDelayMs ? config_.maxDelayMs : delay;
    }
    // EXPONENTIAL: base * 2^(retryCount-1)
    int32_t delay = config_.baseDelayMs;
    for (int32_t i = 1; i < retryCount_; i++) {
        if (delay > config_.maxDelayMs / 2) {
            return config_.maxDelayMs;
        }
        delay *= 2;
        if (delay > config_.maxDelayMs) {
            return config_.maxDelayMs;
        }
    }
    return delay > config_.maxDelayMs ? config_.maxDelayMs : delay;
}

const RetryPolicyConfig &RetryPolicy::GetConfig() const
{
    return config_;
}

void RetryPolicy::SetConfig(const RetryPolicyConfig &config)
{   
    config_ = {
        std::max(config.maxRetryCount, 0),
        config.strategyType,
        std::max(config.baseDelayMs, 0),
        std::max(config.maxDelayMs, 0),
    };
}

bool RetryPolicy::IsSendRequestFailed() const
{
    return sendRequestFailed_;
}

void RetryPolicy::SetSendRequestFailed(bool failed)
{
    sendRequestFailed_ = failed;
}

bool RetryPolicy::IsDisconnectFailed() const
{
    return disconnectFailed_;
}

void RetryPolicy::SetDisconnectFailed(bool failed)
{
    disconnectFailed_ = failed;
}

}  // namespace AppExecFwk
}  // namespace OHOS