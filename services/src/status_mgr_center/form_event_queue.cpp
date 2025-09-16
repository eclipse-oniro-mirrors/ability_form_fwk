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

#include "status_mgr_center/form_event_queue.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "status_mgr_center/form_status.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t EVENT_QUEUE_SIZE_MAX = 100;
}
FormEventQueue::FormEventQueue(int64_t formId) : formId_(formId)
{
    HILOG_INFO("create FormEventQueue, formId :%{public}" PRId64 ". ", formId_);
}

FormEventQueue::~FormEventQueue()
{
    HILOG_INFO("destroy FormEventQueue, formId :%{public}" PRId64 ". ", formId_);
}

bool FormEventQueue::PushFormEvent(FormEventTaskInfo &eventInfo)
{
    std::lock_guard<std::mutex> lock(eventQueueMutex_);
    HILOG_INFO("formId :%{public}" PRId64 ". ", formId_);
    if (eventInfo.getFormId() != formId_) {
        HILOG_ERROR("formId is invalid");
        return false;
    }
    if (eventQueue_.size() >= EVENT_QUEUE_SIZE_MAX) {
        HILOG_ERROR("queue size reached max, formId :%{public}" PRId64 ". ", formId_);
        ReportQueueOverLimit(formId_);
        return false;
    }

    eventQueue_.push(eventInfo);
    return true;
}

bool FormEventQueue::PopFormEvent(FormEventTaskInfo &eventInfo)
{
    std::lock_guard<std::mutex> lock(eventQueueMutex_);
    if (eventQueue_.empty()) {
        HILOG_INFO("eventQueue_ is empty, formId :%{public}" PRId64 ". ", formId_);
        return false;
    }
    HILOG_INFO("eventQueue_ not empty, formId :%{public}" PRId64 ". ", formId_);
    eventInfo = eventQueue_.front();
    eventQueue_.pop();
    return true;
}

bool FormEventQueue::IsEventQueueEmpty()
{
    std::lock_guard<std::mutex> lock(eventQueueMutex_);
    if (eventQueue_.empty()) {
        HILOG_INFO("eventQueue_ is empty, formId :%{public}" PRId64 ".", formId_);
        return true;
    }
    HILOG_INFO("eventQueue_ not empty, formId :%{public}" PRId64 ". ", formId_);
    return false;
}

const std::queue<FormEventTaskInfo> &FormEventQueue::GetEventQueue()
{
    std::lock_guard<std::mutex> lock(eventQueueMutex_);
    return eventQueue_;
}

bool FormEventQueue::ReportQueueOverLimit(const int64_t formId)
{
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return false;
    }
    if (eventQueue_.empty()) {
        HILOG_ERROR("eventQueue_ is empty, formId :%{public}" PRId64 ".", formId);
        return false;
    }

    FormEventTaskInfo eventInfo = eventQueue_.front();
    FormFsmStatus status = FormStatus::GetInstance().GetFormStatus(formId);
    FormEventReport::SendFormFailedEvent(FormEventName::FORM_EVENT_QUEUE_OVER_LIMIT,
        formId,
        formRecord.bundleName,
        formRecord.formName,
        static_cast<int32_t>(status),
        static_cast<int32_t>(eventInfo.getFormEvent()));
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
