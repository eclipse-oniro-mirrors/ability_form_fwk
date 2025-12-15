/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "common/util/form_serial_queue.h"

#include <limits>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
using namespace ffrt;
namespace {
constexpr uint32_t CONVERSION_FACTOR = 1000; // ms to us
}

FormSerialQueue::FormSerialQueue(const std::string &queueName): queue_(queueName.c_str())
{
    HILOG_DEBUG("create FormSerialQueue, queueName :%{public}s", queueName.c_str());
}

FormSerialQueue::~FormSerialQueue()
{
    HILOG_DEBUG("destroy FormSerialQueue");
}

bool FormSerialQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleTask");
    if (ms > (std::numeric_limits<uint64_t>::max() / CONVERSION_FACTOR)) {
        HILOG_ERROR("invalid ms,ScheduleTask failed");
        return false;
    }
    std::unique_lock<ffrt::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return false;
    }
    HILOG_DEBUG("ScheduleTask success");
    return true;
}

bool FormSerialQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask");
    std::unique_lock<ffrt::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return false;
    }
    taskMap_[eventMsg] = std::move(task_handle);
    HILOG_DEBUG("ScheduleDelayTask success");
    return true;
}

bool FormSerialQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("begin to CancelDelayTask");
    std::unique_lock<ffrt::shared_mutex> lock(mutex_);
    auto item = taskMap_.find(eventMsg);
    if (item == taskMap_.end()) {
        HILOG_ERROR("invalid task");
        return false;
    }
    bool result = true;
    if (item->second != nullptr) {
        int32_t ret = queue_.cancel(item->second);
        if (ret != 0) {
            HILOG_ERROR("CancelDelayTask failed,errCode :%{public}d", ret);
            result = false;
        }
    }
    taskMap_.erase(eventMsg);
    HILOG_DEBUG("CancelDelayTask success");
    return result;
}

bool FormSerialQueue::ScheduleDelayTask(
    const std::pair<int64_t, std::string> &eventMsg, uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask");
    std::unique_lock<ffrt::shared_mutex> lock(stringTaskMutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return false;
    }
    stringTaskMap_[eventMsg] = std::move(task_handle);
    HILOG_DEBUG("ScheduleDelayTask success");
    return true;
}

bool FormSerialQueue::CancelDelayTask(const std::pair<int64_t, std::string> &eventMsg)
{
    HILOG_DEBUG("begin to CancelDelayTask");
    std::unique_lock<ffrt::shared_mutex> lock(stringTaskMutex_);
    auto item = stringTaskMap_.find(eventMsg);
    if (item == stringTaskMap_.end()) {
        HILOG_ERROR("invalid task");
        return false;
    }
    bool result = true;
    if (item->second != nullptr) {
        int32_t ret = queue_.cancel(item->second);
        if (ret != 0) {
            HILOG_ERROR("CancelDelayTask failed,errCode :%{public}d", ret);
            result = false;
        }
    }
    stringTaskMap_.erase(eventMsg);
    HILOG_DEBUG("CancelDelayTask success");
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS
