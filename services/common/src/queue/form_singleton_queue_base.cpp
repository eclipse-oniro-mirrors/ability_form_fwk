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

#include "queue/form_singleton_queue_base.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace Common {

FormSingletonQueueBase::FormSingletonQueueBase(const std::string &queueName,
    std::shared_ptr<ITaskWrapperStrategy> strategy)
    : queueName_(queueName),
      serialQueue_(std::make_shared<FormBaseSerialQueue>(queueName)),
      strategy_(strategy ? strategy : std::make_shared<NoWrapStrategy>())
{
    HILOG_INFO("create queue: %{public}s", queueName_.c_str());
}

FormSingletonQueueBase::~FormSingletonQueueBase()
{
    HILOG_INFO("destroy queue: %{public}s", queueName_.c_str());
}

bool FormSingletonQueueBase::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }
    return serialQueue_->ScheduleTask(ms, strategy_->Wrap(std::move(func)));
}

bool FormSingletonQueueBase::ScheduleDelayTask(
    const TaskKey &taskKey, uint64_t ms, std::function<void()> func)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }
    return serialQueue_->ScheduleDelayTask(taskKey, ms, strategy_->Wrap(std::move(func)));
}

bool FormSingletonQueueBase::CancelDelayTask(const TaskKey &taskKey)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }
    return serialQueue_->CancelDelayTask(taskKey);
}

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS