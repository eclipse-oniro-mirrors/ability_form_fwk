/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "status_mgr_center/form_status_queue.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *FORM_STATUS_QUEUE = "FormStatusQueue";
}
FormStatusQueue::FormStatusQueue()
{
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_STATUS_QUEUE);
    HILOG_INFO("create FormStatusQueue");
}

FormStatusQueue::~FormStatusQueue()
{
    HILOG_INFO("destroy FormStatusQueue");
}

bool FormStatusQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    return serialQueue_->ScheduleTask(ms, func);
}

bool FormStatusQueue::ScheduleDelayTask(
    const std::pair<int64_t, int64_t> &eventMsg, uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    return serialQueue_->ScheduleDelayTask(eventMsg, ms, func);
}

bool FormStatusQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    return serialQueue_->CancelDelayTask(eventMsg);
}
}  // namespace AppExecFwk
}  // namespace OHOS
