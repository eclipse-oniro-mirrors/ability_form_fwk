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

#include "status_mgr_center/form_render_status_mgr.h"
#include "status_mgr_center/form_render_status.h"
#include "status_mgr_center/form_render_status_table.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_status_print.h"

namespace OHOS {
namespace AppExecFwk {
FormRenderStatusMgr::FormRenderStatusMgr()
{
    HILOG_DEBUG("create FormRenderStatusMgr");
}

FormRenderStatusMgr::~FormRenderStatusMgr()
{
    HILOG_DEBUG("destroy FormRenderStatusMgr");
}

int32_t FormRenderStatusMgr::PostFormEvent(
    const int64_t formId, const FormFsmEvent event, std::function<int32_t()> func)
{
    // get status machine info
    if (!FormRenderStatus::GetInstance().HasFormStatus(formId)) {
        HILOG_INFO("create new status.");
        FormRenderStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::INIT);
    }
    FormFsmStatus status = FormRenderStatus::GetInstance().GetFormStatus(formId);

    FormRenderStatusMachineInfo info;
    if (!FormRenderStatusTable::GetInstance().GetFormStatusInfo(status, event, info)) {
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    HILOG_INFO("formId:%{public}" PRId64 ", status is %{public}s, event is %{public}s, nextStatus is %{public}s.",
        formId,
        FormStatusPrint::FormStatusToString(status).c_str(),
        FormStatusPrint::FormEventToString(event).c_str(),
        FormStatusPrint::FormStatusToString(info.nextStatus).c_str());

    // state machine switches to the next state.
    FormRenderStatus::GetInstance().SetFormStatus(formId, info.nextStatus);

    // state machine excute
    return ExecFormTask(info.processType, formId, event, status, func);
}

int32_t FormRenderStatusMgr::ExecFormTask(FormFsmProcessType processType, const int64_t formId,
    const FormFsmEvent event, const FormFsmStatus status, std::function<int32_t()> func)
{
    switch (processType) {
        case FormFsmProcessType::PROCESS_TASK_DIRECT:
            return ProcessTaskDirect(func);
        case FormFsmProcessType::PROCESS_TASK_DELETE:
            return ProcessTaskDelete(formId);
        default:
            return PrintTaskInfo(formId, event, status);
    }
}

std::string FormRenderStatusMgr::GetFormEventId(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    if (formEventIdMap_.find(formId) == formEventIdMap_.end()) {
        return "";
    }

    return formEventIdMap_[formId];
}

void FormRenderStatusMgr::SetFormEventId(const int64_t formId, std::string &eventId)
{
    std::unique_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    if (formEventIdMap_.find(formId) == formEventIdMap_.end()) {
        formEventIdMap_.emplace(formId, eventId);
        return;
    }
    formEventIdMap_[formId] = eventId;
}

void FormRenderStatusMgr::DeleteFormEventId(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formEventIdMapMutex_);
    auto iter = formEventIdMap_.find(formId);
    if (iter != formEventIdMap_.end()) {
        HILOG_INFO("formId:%{public}" PRId64 ". ", formId);
        formEventIdMap_.erase(iter);
    }
}

int32_t FormRenderStatusMgr::ProcessTaskDirect(std::function<int32_t()> func)
{
    return func();
}

int32_t FormRenderStatusMgr::ProcessTaskDelete(const int64_t formId)
{
    DeleteFormEventId(formId);
    FormRenderStatus::GetInstance().DeleteFormStatus(formId);
    return ERR_OK;
}

int32_t FormRenderStatusMgr::PrintTaskInfo(const int64_t formId, const FormFsmEvent event, const FormFsmStatus status)
{
    HILOG_ERROR("formId:%{public}" PRId64 ", status is %{public}s, event is %{public}s.",
        formId,
        FormStatusPrint::FormStatusToString(status).c_str(),
        FormStatusPrint::FormEventToString(event).c_str());
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
