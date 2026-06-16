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

#ifndef OHOS_FORM_FWK_TASK_WRAPPER_STRATEGY_H
#define OHOS_FORM_FWK_TASK_WRAPPER_STRATEGY_H

#include <functional>
#include <memory>
#include <string>
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {
namespace {
constexpr int32_t QUEUE_TASK_TIME_OUT = 5;
}
/**
 * @brief Interface for task wrapper strategy.
 *
 * Provides a mechanism to wrap task functions with additional functionality
 * such as timeout monitoring, logging, or other cross-cutting concerns.
 */
class ITaskWrapperStrategy {
public:
    virtual ~ITaskWrapperStrategy() = default;

    /**
     * @brief Wrap a task function with additional functionality.
     * @param func Original task function to wrap.
     * @return Wrapped task function.
     */
    virtual std::function<void()> Wrap(std::function<void()> func) = 0;
};

/**
 * @brief No-operation wrapper strategy.
 *
 * Returns the original task function unchanged without any additional wrapping.
 */
class NoWrapStrategy : public ITaskWrapperStrategy {
public:
    /**
     * @brief Wrap implementation that returns original function.
     * @param func Original task function.
     * @return Same function unchanged.
     */
    std::function<void()> Wrap(std::function<void()> func) override
    {
        return func;
    }
};

/**
 * @brief XCollie timeout monitoring wrapper strategy.
 *
 * Wraps task functions with HiviewDFX::XCollie timeout monitoring.
 * Sets a timer before task execution and cancels it after completion.
 * If task execution exceeds timeout, XCollie will log a timeout event.
 */
class XCollieTimeoutStrategy : public ITaskWrapperStrategy {
public:
    /**
     * @brief Constructor with timeout and tag parameters.
     * @param timeoutSeconds Timeout duration in seconds, default 5.
     * @param tag Tag for XCollie timer identification, default "FMS_QueueTask".
     */
    explicit XCollieTimeoutStrategy(int32_t timeoutSeconds = QUEUE_TASK_TIME_OUT, std::string tag = "FMS_QueueTask")
        : timeoutSeconds_(timeoutSeconds), tag_(std::move(tag)) {}

    /**
     * @brief Wrap task with XCollie timeout monitoring.
     * @param func Original task function.
     * @return Wrapped function with timeout monitoring.
     */
    std::function<void()> Wrap(std::function<void()> func) override
    {
        return [func = std::move(func), timeout = timeoutSeconds_, tag = tag_]() {
            int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
                tag, timeout, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
            func();
            HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
        };
    }

private:
    const int32_t timeoutSeconds_;
    const std::string tag_;
};

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_TASK_WRAPPER_STRATEGY_H