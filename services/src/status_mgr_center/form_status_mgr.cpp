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

#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_status_queue.h"
#include "status_mgr_center/form_status.h"
#include "status_mgr_center/form_event_timeout_queue.h"
#include "status_mgr_center/form_event_retry_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "fms_log_wrapper.h"
#include "form_status_print.h"

namespace OHOS {
namespace AppExecFwk {
FormStatusMgr::FormStatusMgr()
{
    HILOG_DEBUG("create FormStatusMgr");
}

FormStatusMgr::~FormStatusMgr()
{
    HILOG_DEBUG("destroy FormStatusMgr");
}

void FormStatusMgr::PostFormEvent(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    auto task = [formId, event, func]() {
        FormStatusMgr::GetInstance().ExecStatusMachineTask(formId, event, func);
    };

    FormStatusQueue::GetInstance().ScheduleTask(0, task);
}

void FormStatusMgr::CancelFormEventTimeout(const int64_t formId, std::string eventId)
{
    FormEventTimeoutQueue::GetInstance().CancelDelayTask(std::make_pair(formId, eventId));
}

void FormStatusMgr::ExecFormTaskTimeout(
    const int64_t formId, FormEventTimeout timeoutMs, FormFsmEvent event, FormFsmStatus status)
{
    if (timeoutMs == FormEventTimeout::TIMEOUT_NO_NEED) {
        HILOG_DEBUG("no need exec timeout task, formId:%{public}" PRId64, formId);
        return;
    }

    SetFormEventId(formId);
    std::string eventId = GetFormEventId(formId);
    if (eventId.empty()) {
        HILOG_ERROR("get eventId failed, formId:%{public}" PRId64, formId);
        return;
    }

    auto timeoutTask = [formId, event, status, eventId]() {
        HILOG_ERROR("excute timeout, event:%{public}s, status:%{public}s, formId:%{public}" PRId64,
            FormStatusPrint::FormEventToString(event).c_str(),
            FormStatusPrint::FormStatusToString(status).c_str(),
            formId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::EXECUTION_TIMEOUT);
        FormEventTimeoutQueue::GetInstance().CancelDelayTask(std::make_pair(formId, eventId));
    };
    FormEventTimeoutQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(formId, eventId), static_cast<uint32_t>(timeoutMs), timeoutTask);
}

bool FormStatusMgr::ExecStatusMachineTask(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    // get status machine info
    if (!FormStatus::GetInstance().HasFormStatus(formId)) {
        HILOG_INFO("create new status.");
        FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::INIT);
    }
    FormFsmStatus status = FormStatus::GetInstance().GetFormStatus(formId);

    FormStatusMachineInfo info;
    if (!FormStatusTable::GetInstance().GetFormStatusInfo(status, event, info)) {
        HILOG_ERROR("get form status info failed, formId:%{public}" PRId64, formId);
        return false;
    }

    HILOG_INFO("state transition, formId:%{public}" PRId64
        ", status is %{public}s, event is %{public}s, nextStatus is %{public}s, processType is %{public}d.",
        formId,
        FormStatusPrint::FormStatusToString(status).c_str(),
        FormStatusPrint::FormEventToString(event).c_str(),
        FormStatusPrint::FormStatusToString(info.nextStatus).c_str(),
        static_cast<int32_t>(info.processType));

    // state machine switches to the next state.
    FormStatus::GetInstance().SetFormStatus(formId, info.nextStatus);

    // state machine timeout process
    FormStatusMgr::GetInstance().ExecFormTaskTimeout(formId, info.timeoutMs, event, status);

    // state machine excute
    FormStatusMgr::GetInstance().ExecFormTask(info.processType, formId, event, func);
    return true;
}

void FormStatusMgr::ExecFormTask(
    FormFsmProcessType processType, const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    switch (processType) {
        case FormFsmProcessType::PROCESS_TASK_DIRECT:
            ProcessTaskDirect(formId, event, func);
            break;
        case FormFsmProcessType::ADD_TASK_TO_QUEUE_UNIQUE:
            AddTaskToQueueUnique(formId, event, func);
            break;
        case FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH:
            AddTaskToQueuePush(formId, event, func);
            break;
        case FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE:
            AddTaskToQueueDelete(formId, event, func);
            break;
        case FormFsmProcessType::PROCESS_TASK_FROM_QUEUE:
            ProcessTaskFromQueue(formId);
            break;
        case FormFsmProcessType::PROCESS_TASK_DELETE:
            ProcessTaskDelete(formId);
            break;
        case FormFsmProcessType::PROCESS_TASK_RETRY:
            ProcessTaskFromRetry(formId);
            break;
        default:
            break;
    }
}

void FormStatusMgr::ProcessTaskDirect(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    if (func == nullptr) {
        HILOG_ERROR("func is nullptr");
        return;
    }

    FormEventTaskInfo taskInfo{formId, event, func};
    FormEventRetryMgr::GetInstance().SetLastFormEvent(formId, taskInfo);

    func();
}

void FormStatusMgr::AddTaskToQueueUnique(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    std::shared_ptr<FormEventQueue> formEventQueue = GetFormEventQueue(formId);

    FormEventTaskInfo taskInfo{formId, event, func};
    if (!(formEventQueue->PushFormEvent(taskInfo))) {
        HILOG_ERROR("push form event error, formId :%{public}" PRId64 ". ", formId);
        return;
    }

    std::queue<FormEventTaskInfo> temptaskInfoQueue;
    while (!formEventQueue->IsEventQueueEmpty()) {
        FormEventTaskInfo eventTaskInfo{};
        if (!formEventQueue->PopFormEvent(eventTaskInfo)) {
            HILOG_INFO("formEventQueue is empty.");
            break;
        }
        if (eventTaskInfo.getFormEvent() == FormFsmEvent::RENDER_FORM ||
            eventTaskInfo.getFormEvent() == FormFsmEvent::DELETE_FORM) {
            temptaskInfoQueue.push(eventTaskInfo);
        }
    }

    while (!temptaskInfoQueue.empty()) {
        FormEventTaskInfo eventTaskInfo = temptaskInfoQueue.front();
        temptaskInfoQueue.pop();
        formEventQueue->PushFormEvent(eventTaskInfo);
    }
    HILOG_INFO("formEventQueue event size %{public}d.", static_cast<int32_t>(formEventQueue->GetEventQueue().size()));

    FormDataMgr::GetInstance().UpdateFormRecordSetIsExistRecycleTask(formId, false);
}

void FormStatusMgr::AddTaskToQueuePush(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    std::shared_ptr<FormEventQueue> formEventQueue = GetFormEventQueue(formId);
    FormEventTaskInfo taskInfo{formId, event, func};
    formEventQueue->PushFormEvent(taskInfo);

    if (event == FormFsmEvent::RECYCLE_DATA || event == FormFsmEvent::RECYCLE_FORM) {
        FormDataMgr::GetInstance().UpdateFormRecordSetIsExistRecycleTask(formId, true);
    }
}

void FormStatusMgr::AddTaskToQueueDelete(const int64_t formId, const FormFsmEvent event, std::function<void()> func)
{
    FormDataMgr::GetInstance().UpdateFormRecordSetIsExistRecycleTask(formId, false);

    std::shared_ptr<FormEventQueue> formEventQueue = GetFormEventQueue(formId);
    FormEventTaskInfo taskInfo{formId, event, func};
    if (formEventQueue->IsEventQueueEmpty()) {
        formEventQueue->PushFormEvent(taskInfo);
        return;
    }

    while (!formEventQueue->IsEventQueueEmpty()) {
        FormEventTaskInfo eventTaskInfo{};
        if (!formEventQueue->PopFormEvent(eventTaskInfo)) {
            HILOG_INFO("formEventQueue is empty.");
            break;
        }
    }
    formEventQueue->PushFormEvent(taskInfo);
    HILOG_INFO("formEventQueue event size %{public}d.", static_cast<int32_t>(formEventQueue->GetEventQueue().size()));
}

void FormStatusMgr::ProcessTaskFromQueue(const int64_t formId)
{
    if (!HasFormEventQueue(formId)) {
        HILOG_INFO("formEventQueue is empty, not process.");
        return;
    }
    std::shared_ptr<FormEventQueue> formEventQueue = GetFormEventQueue(formId);

    FormEventTaskInfo eventTaskInfo{};
    if (!formEventQueue->PopFormEvent(eventTaskInfo)) {
        HILOG_INFO("formEventQueue is empty, not process.");
        return;
    }

    auto func = eventTaskInfo.getFunc();
    auto event = eventTaskInfo.getFormEvent();
    if (event == FormFsmEvent::RECYCLE_FORM) {
        FormDataMgr::GetInstance().UpdateFormRecordSetIsExistRecycleTask(formId, false);
    }

    FormStatusMgr::GetInstance().ExecStatusMachineTask(formId, event, func);
}

void FormStatusMgr::ProcessTaskDelete(const int64_t formId)
{
    DeleteFormEventQueue(formId);
    DeleteFormEventId(formId);
    FormStatus::GetInstance().DeleteFormStatus(formId);
    FormEventRetryMgr::GetInstance().DeleteLastFormEvent(formId);
    FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
}

void FormStatusMgr::ProcessTaskFromRetry(const int64_t formId)
{
    int32_t retryCount = FORM_EVENT_RETRY_MAX;
    bool ret = FormEventRetryMgr::GetInstance().GetRetryCount(formId, retryCount);
    if (ret && retryCount == FORM_EVENT_RETRY_MAX) {
        HILOG_INFO("retry reached count.");
        FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
        ProcessTaskFromQueue(formId);
        return;
    }
    HILOG_INFO("set retry count 1.");
    FormEventRetryMgr::GetInstance().SetRetryCount(formId, 1);

    FormEventTaskInfo formEventInfo;
    ret = FormEventRetryMgr::GetInstance().GetLastFormEvent(formId, formEventInfo);
    if (!ret) {
        HILOG_ERROR("GetLastFormEvent failed.");
        return;
    }

    auto func = formEventInfo.getFunc();
    auto event = formEventInfo.getFormEvent();
    FormStatusMgr::GetInstance().ExecStatusMachineTask(formId, event, func);
}

bool FormStatusMgr::HasFormEventQueue(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formEventQueueMutex_);
    return !(formEventQueueMap_.find(formId) == formEventQueueMap_.end());
}

const std::shared_ptr<FormEventQueue> FormStatusMgr::GetFormEventQueue(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formEventQueueMutex_);
    if (formEventQueueMap_.find(formId) == formEventQueueMap_.end()) {
        std::shared_ptr<FormEventQueue> formEventQueue = std::make_shared<FormEventQueue>(formId);
        formEventQueueMap_.emplace(formId, formEventQueue);
        HILOG_INFO("formEventQueueMap_ insert, formId:%{public}" PRId64 ". ", formId);
    }

    return formEventQueueMap_[formId];
}

void FormStatusMgr::DeleteFormEventQueue(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formEventQueueMutex_);
    auto iter = formEventQueueMap_.find(formId);
    if (iter != formEventQueueMap_.end()) {
        HILOG_INFO("formId:%{public}" PRId64 ". ", formId);
        formEventQueueMap_.erase(iter);
    }
}

std::string FormStatusMgr::GetFormEventId(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    if (formEventIdMap_.find(formId) == formEventIdMap_.end()) {
        HILOG_ERROR("eventId is not existed, formId:%{public}" PRId64 ".", formId);
        return "";
    }

    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s.", formId, (formEventIdMap_[formId]).c_str());
    return formEventIdMap_[formId];
}

void FormStatusMgr::SetFormEventId(const int64_t formId)
{
    int64_t eventId = FormUtil::GetCurrentNanosecond();
    std::string tidString = std::to_string(eventId);
    HILOG_INFO("formId:%{public}" PRId64 ", eventId:%{public}s.", formId, tidString.c_str());
    std::unique_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    if (formEventIdMap_.find(formId) == formEventIdMap_.end()) {
        formEventIdMap_.emplace(formId, std::to_string(eventId));
        return;
    }
    formEventIdMap_[formId] = tidString;
}

void FormStatusMgr::DeleteFormEventId(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    auto iter = formEventIdMap_.find(formId);
    if (iter != formEventIdMap_.end()) {
        HILOG_INFO("formId:%{public}" PRId64 ". ", formId);
        formEventIdMap_.erase(iter);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
