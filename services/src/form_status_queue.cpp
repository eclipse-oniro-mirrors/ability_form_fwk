/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
 
#include <limits>

#include "form_status_queue.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_host_interface.h"

namespace OHOS {
namespace AppExecFwk {
using namespace ffrt;
namespace {
constexpr uint32_t CONVERSION_FACTOR = 1000; // ms to us
const std::string FORM_STATUS_QUEUE = "FormStatusQueue";
}

FormStatusQueue::FormStatusQueue(): queue_(FORM_STATUS_QUEUE.c_str())
{
    HILOG_DEBUG("create FormStatusQueue, queueName :%{public}s", FORM_STATUS_QUEUE.c_str());
}

FormStatusQueue::~FormStatusQueue()
{
    HILOG_DEBUG("destroy FormStatusQueue");
}

bool FormStatusQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
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

void FormStatusQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
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

void FormStatusQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
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

std::shared_ptr<FormCommandQueue> FormStatusQueue::GetOrCreateFormStatusQueue(
    const int64_t formId, const sptr<IRemoteObject> &remoteObjectOfHost, FormStatus formStatus)
{
    if (formCommandQueueMap_.find(formId) == formCommandQueueMap_.end()) {
        std::shared_ptr<FormCommandQueue> formCommandQueue = std::make_shared<FormCommandQueue>(formId);
        formCommandQueueMap_.emplace(std::make_pair(formId, formCommandQueue));
        FormStatusMgr::GetInstance().AddFormStatus(formId, formStatus);
        HILOG_INFO("formCommandQueueMap_ insert, formId:%{public}" PRId64 ". ", formId);
    }

    if (formHostTokenMap_.find(formId) == formHostTokenMap_.end()) {
        formHostTokenMap_.emplace(std::make_pair(formId, remoteObjectOfHost));
        HILOG_INFO("formHostTokenMap_ insert, formId:%{public}" PRId64 ". ", formId);
    }
    return formCommandQueueMap_[formId];
}

void FormStatusQueue::DeleteFormStatusQueue(const int64_t formId)
{
    formCommandQueueMap_.erase(formId);
    formHostTokenMap_.erase(formId);
    FormStatusMgr::GetInstance().DeleteFormStatus(formId);
    HILOG_INFO("formCommandQueueMap_ erase, formId:%{public}" PRId64 ". ", formId);
}

void FormStatusQueue::PostFormStatusTask(FormCommand formCommand, sptr<IRemoteObject> remoteObjectOfHost)
{
    auto formId = formCommand.getFormId();
    auto taskCommandType = formCommand.getEventMsg().first;
    std::unique_lock<std::shared_mutex> lock(formCommandQueueMapMutex_);
    std::shared_ptr<FormCommandQueue> formCommandQueue;
    if (taskCommandType == TaskCommandType::RENDER_FORM || taskCommandType == TaskCommandType::RECYCLE_FORM) {
        formCommandQueue = GetOrCreateFormStatusQueue(formId, remoteObjectOfHost, FormStatus::RECOVERED);
    } else if (taskCommandType == TaskCommandType::RECOVER_FORM) {
        formCommandQueue = GetOrCreateFormStatusQueue(formId, remoteObjectOfHost, FormStatus::RECYCLED);
    } else {
        HILOG_ERROR("taskCommandType is unknown , formId:%{public}" PRId64 ". ", formId);
        return;
    }
    if (formCommandQueue == nullptr) {
        HILOG_ERROR("formCommandQueue is null , formId:%{public}" PRId64 ". ", formId);
        return;
    }

    formCommandQueue->PushFormCommand(formCommand);
    PostFormCommandTask(formCommandQueue, formId);
}

void FormStatusQueue::PostFormDeleteTask(FormCommand formCommand, const std::string compId)
{
    auto formId = formCommand.getFormId();
    auto ms = formCommand.getMs();
    auto func = formCommand.getFunc();
    HILOG_INFO("PostFormDeleteTask , formId:%{public}" PRId64 ". ", formId);
    {
        std::unique_lock<std::shared_mutex> lock(formCommandQueueMapMutex_);
        if (compId.empty() ||
            formCommandQueueMap_.find(formId) == formCommandQueueMap_.end() ||
            formCommandQueueMap_[formId]->IsCommondQueueEmpty()) {
            DeleteFormStatusQueue(formId);
        }
    }
    ScheduleTask(ms, func);
}

void FormStatusQueue::PostFormCommandTask(std::shared_ptr<FormCommandQueue> formCommandQueue, const int64_t formId)
{
    if (FormStatusMgr::GetInstance().isProcessableFormStatus(formId)) {
        FormCommand formCommand{};
        if (!formCommandQueue->PopFormCommand(formCommand)) {
            HILOG_INFO("formCommandQueue is empty, formId:%{public}" PRId64 ". ", formId);
            return;
        }
        ProcessTask(formCommand);
    } else {
        HILOG_INFO("FormStatus is unProcessable, formId:%{public}" PRId64 ". ", formId);
    }
}

void FormStatusQueue::PostFormCommandTaskByFormId(const int64_t formId)
{
    if (FormStatusMgr::GetInstance().isProcessableFormStatus(formId)) {
        std::shared_ptr<FormCommandQueue> formCommandQueue;
        {
            std::shared_lock<std::shared_mutex> lock(formCommandQueueMapMutex_);
            if (formCommandQueueMap_.find(formId) == formCommandQueueMap_.end()) {
                HILOG_ERROR("formCommandQueueMap_ query failed, formId:%{public}" PRId64 ". ", formId);
                return;
            }
            formCommandQueue = formCommandQueueMap_[formId];
        }

        FormCommand formCommand{};
        if (!formCommandQueue->PopFormCommand(formCommand)) {
            HILOG_INFO("formCommandQueue is empty, formId:%{public}" PRId64 ". ", formId);
            return;
        }
        ProcessTask(formCommand);
    } else {
        HILOG_INFO("FormStatus is unProcessable, formId:%{public}" PRId64 ". ", formId);
    }
}

void FormStatusQueue::ProcessTask(FormCommand &formCommand)
{
    auto taskCommandType = formCommand.getEventMsg().first;
    auto formId = formCommand.getFormId();
    auto ms = formCommand.getMs();
    auto func = formCommand.getFunc();

    if (taskCommandType == TaskCommandType::RENDER_FORM) {
        FormStatusMgr::GetInstance().SetFormStatus(formId, FormStatus::UNPROCESSABLE);
        ScheduleTask(ms, func);
    } else if (taskCommandType == TaskCommandType::RECOVER_FORM) {
        FormStatusMgr::GetInstance().SetFormStatus(formId, FormStatus::RECOVERING);
        ScheduleTask(ms, func);
    } else if (taskCommandType == TaskCommandType::RECYCLE_FORM) {
        FormStatusMgr::GetInstance().SetFormStatus(formId, FormStatus::RECYCLING);
        ScheduleTask(ms, func);
    } else {
        HILOG_ERROR("ProcessTask Error!, formId :%{public}" PRId64 ". ", formId);
    }
}

void FormStatusQueue::PostTimeOutReAddForm(const int64_t formId)
{
    HILOG_DEBUG("start");
    if (formHostTokenMap_.find(formId) == formHostTokenMap_.end() || formHostTokenMap_[formId] == nullptr) {
        HILOG_ERROR("formHostToken is null, formId:%{public}" PRId64 ". ", formId);
        return;
    }
    auto remoteObjectOfHost = formHostTokenMap_[formId];
    auto timeOutReAddForm = [formId, remoteObjectOfHost]() {
        FormStatusQueue::GetInstance().TimeOutReAddForm(formId, remoteObjectOfHost);
    };
    ScheduleDelayTask(
        std::make_pair((int64_t)TaskCommandType::READDFORM_FORM, formId),
        FORM_MAX_TIME_OUT,
        timeOutReAddForm);
    HILOG_DEBUG("end");
}

void FormStatusQueue::TimeOutReAddForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost)
{
    HILOG_INFO("start");
    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObjectOfHost);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }
    remoteFormHost->OnError(ERR_APPEXECFWK_FORM_STATUS_TIMIE_OUT, "form status timeout, try reAddForm.");
    HILOG_INFO("end");
}

void FormStatusQueue::CancelTimeOutReAddForm(const int64_t &formId)
{
    CancelDelayTask(std::make_pair((int64_t)TaskCommandType::READDFORM_FORM, formId));
}
}  // namespace AppExecFwk
}  // namespace OHOS
