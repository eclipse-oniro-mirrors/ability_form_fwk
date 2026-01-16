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
 
#include "form_mgr/form_mgr_queue.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *FORM_MGR_QUEUE = "FormMgrQueue";
}
FormMgrQueue::FormMgrQueue()
{
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_MGR_QUEUE);
    HILOG_INFO("create FormMgrQueue");
}

FormMgrQueue::~FormMgrQueue()
{
    HILOG_INFO("destroy FormMgrQueue");
}
 
bool FormMgrQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    auto task = [func = std::move(func)] () {
        int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_QueueTak",
            QUEUE_TASK_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
        func();
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    };
 
    return serialQueue_->ScheduleTask(ms, task);
}
 
void FormMgrQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }

    auto task = [func = std::move(func)] () {
        int timerId = HiviewDFX::XCollie::GetInstance().SetTimer("FMS_QueueTak",
            QUEUE_TASK_TIME_OUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
        func();
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    };
 
    serialQueue_->ScheduleDelayTask(eventMsg, ms, task);
}

void FormMgrQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
 
    serialQueue_->CancelDelayTask(eventMsg);
}
} // namespace AppExecFwk
} // namespace OHOS