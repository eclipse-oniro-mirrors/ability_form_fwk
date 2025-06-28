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
    std::unique_lock<std::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return false;
    }
    HILOG_DEBUG("ScheduleTask success");
    return true;
}

void FormSerialQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask");
    std::unique_lock<std::shared_mutex> lock(mutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return;
    }
    taskMap_[eventMsg] = std::move(task_handle);
    HILOG_DEBUG("ScheduleDelayTask success");
}

void FormSerialQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("begin to CancelDelayTask");
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto item = taskMap_.find(eventMsg);
    if (item == taskMap_.end()) {
        HILOG_ERROR("invalid task");
        return;
    }
    if (item->second != nullptr) {
        int32_t ret = queue_.cancel(item->second);
        if (ret != 0) {
            HILOG_ERROR("CancelDelayTask failed,errCode :%{public}d", ret);
        }
    }
    taskMap_.erase(eventMsg);
    HILOG_DEBUG("CancelDelayTask success");
}

void FormSerialQueue::ScheduleDelayTask(
    const std::pair<int64_t, std::string> &eventMsg, uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask");
    std::unique_lock<std::shared_mutex> lock(stringTaskMutex_);
    task_handle task_handle = queue_.submit_h(func, task_attr().delay(ms * CONVERSION_FACTOR));
    if (task_handle == nullptr) {
        HILOG_ERROR("null task_handle");
        return;
    }
    stringTaskMap_[eventMsg] = std::move(task_handle);
    HILOG_DEBUG("ScheduleDelayTask success");
}

void FormSerialQueue::CancelDelayTask(const std::pair<int64_t, std::string> &eventMsg)
{
    HILOG_DEBUG("begin to CancelDelayTask");
    std::unique_lock<std::shared_mutex> lock(stringTaskMutex_);
    auto item = stringTaskMap_.find(eventMsg);
    if (item == stringTaskMap_.end()) {
        HILOG_ERROR("invalid task");
        return;
    }
    if (item->second != nullptr) {
        int32_t ret = queue_.cancel(item->second);
        if (ret != 0) {
            HILOG_ERROR("CancelDelayTask failed,errCode :%{public}d", ret);
        }
    }
    stringTaskMap_.erase(eventMsg);
    HILOG_DEBUG("CancelDelayTask success");
}

int FormSerialQueue::TestFormId1(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId2(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId3(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId4(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId5(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId6(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId7(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId8(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId9(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId10(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId11(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId12(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId13(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId14(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormSerialQueue::TestFormId15(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
