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

#include "queue/form_base_serial_queue.h"

#include <limits>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {
namespace {
constexpr uint32_t CONVERSION_FACTOR = 1000; // ms to us
}

FormBaseSerialQueue::FormBaseSerialQueue(const std::string &queueName)
    : queueName_(queueName), queue_(queueName.c_str())
{
    HILOG_DEBUG("create FormBaseSerialQueue, queueName: %{public}s", queueName.c_str());
}

FormBaseSerialQueue::~FormBaseSerialQueue()
{
    HILOG_DEBUG("destroy FormBaseSerialQueue");
}

bool FormBaseSerialQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("ScheduleTask");
    if (ms > (std::numeric_limits<uint64_t>::max() / CONVERSION_FACTOR)) {
        HILOG_ERROR("invalid ms");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ffrt::task_handle handle = queue_.submit_h(func,
        ffrt::task_attr().delay(ms * CONVERSION_FACTOR));
    if (handle == nullptr) {
        HILOG_ERROR("submit_h return null");
        return false;
    }
    return true;
}

bool FormBaseSerialQueue::ScheduleDelayTask(const TaskKey& taskKey,
    uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("ScheduleDelayTask");
    if (ms > (std::numeric_limits<uint64_t>::max() / CONVERSION_FACTOR)) {
        HILOG_ERROR("invalid ms");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // If a task with the same key exists, cancel it first
    auto it = taskMap_.find(taskKey);
    if (it != taskMap_.end()) {
        queue_.cancel(it->second);
        taskMap_.erase(it);
    }

    ffrt::task_handle handle = queue_.submit_h(func,
        ffrt::task_attr().delay(ms * CONVERSION_FACTOR));
    if (handle == nullptr) {
        HILOG_ERROR("submit_h return null");
        return false;
    }

    taskMap_[taskKey] = std::move(handle);
    return true;
}

bool FormBaseSerialQueue::CancelDelayTask(const TaskKey& taskKey)
{
    HILOG_DEBUG("CancelDelayTask");
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = taskMap_.find(taskKey);
    if (it == taskMap_.end()) {
        HILOG_DEBUG("task not found");
        return false;
    }

    bool result = true;
    if (it->second != nullptr) {
        int32_t ret = queue_.cancel(it->second);
        if (ret != 0) {
            HILOG_ERROR("cancel failed, errCode: %{public}d", ret);
            result = false;
        }
    }

    taskMap_.erase(it);
    return result;
}

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS