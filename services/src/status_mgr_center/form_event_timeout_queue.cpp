/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "status_mgr_center/form_event_timeout_queue.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_EVENT_TIMEOUT_QUEUE = "FormEventTimeoutQueue";
}
FormEventTimeoutQueue::FormEventTimeoutQueue()
{
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_EVENT_TIMEOUT_QUEUE.c_str());
    HILOG_INFO("create FormEventTimeoutQueue");
}

FormEventTimeoutQueue::~FormEventTimeoutQueue()
{
    HILOG_INFO("destroy FormEventTimeoutQueue");
}

bool FormEventTimeoutQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    return serialQueue_->ScheduleTask(ms, func);
}

void FormEventTimeoutQueue::ScheduleDelayTask(
    const std::pair<int64_t, std::string> &eventMsg, uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }

    serialQueue_->ScheduleDelayTask(eventMsg, ms, func);
}

void FormEventTimeoutQueue::CancelDelayTask(const std::pair<int64_t, std::string> &eventMsg)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }

    serialQueue_->CancelDelayTask(eventMsg);
}
}  // namespace AppExecFwk
}  // namespace OHOS