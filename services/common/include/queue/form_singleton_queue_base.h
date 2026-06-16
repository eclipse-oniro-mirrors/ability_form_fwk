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

#ifndef OHOS_FORM_FWK_SINGLETON_QUEUE_BASE_H
#define OHOS_FORM_FWK_SINGLETON_QUEUE_BASE_H

#include <functional>
#include <memory>
#include <string>

#include "queue/form_base_serial_queue.h"
#include "queue/task_wrapper_strategy.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {

/**
 * @brief Singleton queue base implementation with task wrapper strategy support.
 *
 * This class wraps FormBaseSerialQueue and provides the ability to apply
 * task wrapper strategies (e.g., timeout monitoring via XCollie) before
 * scheduling tasks.
 *
 * Features:
 * - Wraps FormBaseSerialQueue for serial task execution
 * - Supports custom task wrapper strategies via ITaskWrapperStrategy
 * - Default uses NoWrapStrategy if no strategy provided
 */
class FormSingletonQueueBase {
public:
    DISALLOW_COPY_AND_MOVE(FormSingletonQueueBase);

    /**
     * @brief Constructor with optional task wrapper strategy.
     * @param queueName Name of the queue for identification.
     * @param strategy Task wrapper strategy, nullptr uses NoWrapStrategy by default.
     */
    explicit FormSingletonQueueBase(
        const std::string &queueName,
        std::shared_ptr<ITaskWrapperStrategy> strategy = nullptr);

    /**
     * @brief Destructor.
     */
    ~FormSingletonQueueBase();

    /**
     * @brief Schedule a one-shot task.
     * @param ms Delay time in milliseconds.
     * @param func Task function to execute.
     * @return true if scheduled successfully, false otherwise.
     */
    bool ScheduleTask(uint64_t ms, std::function<void()> func);

    /**
     * @brief Schedule a delayed task with unified TaskKey.
     * @param taskKey Task identifier (auto-deduced type).
     * @param ms Delay time in milliseconds.
     * @param func Task function to execute.
     * @return true if scheduled successfully, false otherwise.
     */
    bool ScheduleDelayTask(const TaskKey &taskKey, uint64_t ms, std::function<void()> func);

    /**
     * @brief Cancel a delayed task with unified TaskKey.
     * @param taskKey Task identifier.
     * @return true if cancelled successfully, false otherwise.
     */
    bool CancelDelayTask(const TaskKey &taskKey);

private:
    const std::string queueName_;
    const std::shared_ptr<FormBaseSerialQueue> serialQueue_;
    const std::shared_ptr<ITaskWrapperStrategy> strategy_;
};

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_SINGLETON_QUEUE_BASE_H