/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "form_render_serial_queue.h"

#include <limits>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using namespace ffrt;
namespace {
constexpr uint32_t CONVERSION_FACTOR = 1000; // ms to us
}

FormRenderSerialQueue::FormRenderSerialQueue(const std::string &queueName): queue_(queueName.c_str())
{
    HILOG_DEBUG("create FormRenderSerialQueue, queueName :%{public}s", queueName.c_str());
}

FormRenderSerialQueue::~FormRenderSerialQueue()
{
    HILOG_DEBUG("destroy FormRenderSerialQueue");
}

bool FormRenderSerialQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleTask");
    if (ms > (std::numeric_limits<uint64_t>::max() / CONVERSION_FACTOR)) {
        HILOG_ERROR("invalid ms,ScheduleTask failed");
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("submit_h return null");
        return false;
    }
    HILOG_DEBUG("ScheduleTask success");
    return true;
}

bool FormRenderSerialQueue::ScheduleDelayTask(const std::string &taskName,
    uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask %{public}s", taskName.c_str());
    std::unique_lock<std::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("submit_h return null");
        return false;
    }
    taskMap_[taskName] = std::move(task_handle);
    HILOG_DEBUG("ScheduleDelayTask success");
    return true;
}

bool FormRenderSerialQueue::CancelDelayTask(const std::string &taskName)
{
    HILOG_DEBUG("begin to CancelDelayTask %{public}s", taskName.c_str());
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto item = taskMap_.find(taskName);
    if (item == taskMap_.end()) {
        HILOG_DEBUG("invalid task,CancelDelayTask %{public}s failed", taskName.c_str());
        return false;
    }
    if (item->second != nullptr) {
        int32_t ret = queue_.cancel(item->second);
        if (ret != 0) {
            HILOG_ERROR("CancelDelayTask %{public}s failed,errCode:%{public}d", taskName.c_str(), ret);
            return false;
        }
    }
    taskMap_.erase(taskName);
    HILOG_DEBUG("CancelDelayTask success");
    return true;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
