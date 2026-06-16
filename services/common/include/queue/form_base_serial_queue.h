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

#ifndef OHOS_FORM_FWK_BASE_SERIAL_QUEUE_H
#define OHOS_FORM_FWK_BASE_SERIAL_QUEUE_H

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <variant>

#include "ffrt.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {

/**
 * @brief TaskKey type definition using std::variant
 * Supports multiple key types for unified task identification:
 * - int64_t: Single ID (e.g., formId)
 * - std::pair<int64_t, int64_t>: ID pair (formId, eventId)
 * - std::pair<int64_t, std::string>: ID and string pair
 * - std::string: String name (e.g., task name)
 */
using TaskKey = std::variant<
    int64_t,
    std::pair<int64_t, int64_t>,
    std::pair<int64_t, std::string>,
    std::string
>;

/**
 * @brief TaskKey comparator for std::map usage
 * std::variant supports default comparison operator
 */
struct TaskKeyComparator {
    bool operator()(const TaskKey &lhs, const TaskKey &rhs) const
    {
        return lhs < rhs;
    }
};

/**
 * @brief Base serial queue implementation using ffrt
 * Provides unified task scheduling capability with support for:
 * - One-shot task scheduling
 * - Delayed task scheduling with various key types
 * - Task cancellation
 *
 * Uses std::variant (TaskKey) to unify handling of different task identifiers:
 * - int64_t: Single ID
 * - std::pair<int64_t, int64_t>: ID pair (formId, eventId)
 * - std::pair<int64_t, std::string>: ID and string pair
 * - std::string: String name
 */
class FormBaseSerialQueue {
public:
    DISALLOW_COPY_AND_MOVE(FormBaseSerialQueue);

    /**
     * @brief Constructor
     * @param queueName Name of the queue for identification
     */
    explicit FormBaseSerialQueue(const std::string &queueName);

    /**
     * @brief Destructor
     */
    ~FormBaseSerialQueue();

    /**
     * @brief Schedule a one-shot task
     * @param ms Delay time in milliseconds
     * @param func Task function to execute
     * @return true if scheduled successfully, false otherwise
     */
    bool ScheduleTask(uint64_t ms, std::function<void()> func);

    /**
     * @brief Schedule a delayed task with unified TaskKey
     * @param taskKey Task identifier (auto-deduced type)
     * @param ms Delay time in milliseconds
     * @param func Task function to execute
     * @return true if scheduled successfully, false otherwise
     */
    bool ScheduleDelayTask(const TaskKey &taskKey, uint64_t ms, std::function<void()> func);

    /**
     * @brief Cancel a delayed task with unified TaskKey
     * @param taskKey Task identifier
     * @return true if cancelled successfully, false otherwise
     */
    bool CancelDelayTask(const TaskKey &taskKey);

private:
    std::string queueName_;
    ffrt::queue queue_;
    std::mutex mutex_;

    // Unified taskMap using std::variant as key
    std::map<TaskKey, ffrt::task_handle, TaskKeyComparator> taskMap_;
};

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_BASE_SERIAL_QUEUE_H