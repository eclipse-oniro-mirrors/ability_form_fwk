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

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormSerialQueue::FormSerialQueue(const std::string &queueName)
    : baseQueue_(std::make_shared<Common::FormBaseSerialQueue>(queueName))
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
    if (baseQueue_ == nullptr) {
        HILOG_ERROR("baseQueue_ is null");
        return false;
    }
    return baseQueue_->ScheduleTask(ms, func);
}

bool FormSerialQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("begin to ScheduleDelayTask");
    if (baseQueue_ == nullptr) {
        HILOG_ERROR("baseQueue_ is null");
        return false;
    }
    return baseQueue_->ScheduleDelayTask(eventMsg, ms, func);
}

bool FormSerialQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("begin to CancelDelayTask");
    if (baseQueue_ == nullptr) {
        HILOG_ERROR("baseQueue_ is null");
        return false;
    }
    return baseQueue_->CancelDelayTask(eventMsg);
}

}  // namespace AppExecFwk
}  // namespace OHOS