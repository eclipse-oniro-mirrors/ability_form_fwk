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

#include "status_mgr_center/form_render_status_task_mgr.h"

#include "status_mgr_center/form_render_status_mgr.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
namespace {
constexpr int64_t WAIT_RELEASE_RENDERER_TIMEOUT = 3000;
}
FormRenderStatusTaskMgr::FormRenderStatusTaskMgr()
{
    HILOG_DEBUG("create FormRenderStatusTaskMgr");
}

FormRenderStatusTaskMgr::~FormRenderStatusTaskMgr()
{
    HILOG_DEBUG("destroy FormRenderStatusTaskMgr");
}

void FormRenderStatusTaskMgr::OnRenderFormDone(const int64_t formId, const FormFsmEvent event,
    const std::string &eventId, const sptr<IFormSupply> formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    auto replyTask = [formId, event, eventId, formSupplyClient] {
        Want replyWant;
        if (eventId.empty()) {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RENDER_FORM_FAIL));
        } else {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(event));
            replyWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
        }
        return formSupplyClient->OnRenderFormDone(formId, replyWant);
    };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, replyTask);
}

void FormRenderStatusTaskMgr::OnRecycleForm(const int64_t formId, const FormFsmEvent event,
    const std::string &statusData, const Want &want, const sptr<IFormSupply> formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    auto replyTask = [formId, event, statusData, want, formSupplyClient] {
        Want newWant = want;
        newWant.SetParam(Constants::FORM_STATUS_DATA, statusData);
        std::string eventId = want.GetStringParam(Constants::FORM_STATUS_EVENT_ID);
        if (eventId.empty()) {
            newWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_DATA_FAIL));
        } else {
            newWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(event));
            newWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
        }
        return formSupplyClient->OnRecycleForm(formId, newWant);
    };

    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, replyTask);
}

void FormRenderStatusTaskMgr::OnRecoverFormDone(const int64_t formId, const FormFsmEvent event,
    const std::string &eventId, const sptr<IFormSupply> formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    auto replyTask = [formId, event, eventId, formSupplyClient] {
        Want replyWant;
        if (eventId.empty()) {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECOVER_FORM_FAIL));
        } else {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(event));
            replyWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
        }
        return formSupplyClient->OnRecoverFormDone(formId, replyWant);
    };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, replyTask);
}

void FormRenderStatusTaskMgr::OnDeleteFormDone(const int64_t formId, const FormFsmEvent event,
    const std::string &eventId, const sptr<IFormSupply> formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    auto replyTask = [formId, event, eventId, formSupplyClient] {
        Want replyWant;
        if (eventId.empty()) {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::DELETE_FORM_FAIL));
        } else {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(event));
            replyWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
        }
        return formSupplyClient->OnDeleteFormDone(formId, replyWant);
    };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, replyTask);
}

void FormRenderStatusTaskMgr::OnRecycleFormDone(const int64_t formId, const FormFsmEvent event,
    const std::string &eventId, const sptr<IFormSupply> formSupplyClient)
{
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
        return;
    }

    auto replyTask = [formId, event, eventId, formSupplyClient] {
        Want replyWant;
        if (eventId.empty()) {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_FORM_FAIL));
        } else {
            replyWant.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(event));
            replyWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
        }
        return formSupplyClient->OnRecycleFormDone(formId, replyWant);
    };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, replyTask);
}

bool FormRenderStatusTaskMgr::ScheduleRecycleTimeout(const int64_t formId)
{
    FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);

    std::lock_guard<std::mutex> lock(serialQueueMutex_);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    std::string str = std::to_string(formId);
    auto timeoutTask = [formId]() {
        HILOG_ERROR("RecycleForm failed, wait form release timeout, formId:%{public}" PRId64, formId);
        FormRenderStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::UNPROCESSABLE);
        FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);
    };
    return serialQueue_->ScheduleDelayTask(str, WAIT_RELEASE_RENDERER_TIMEOUT, timeoutTask);
}

bool FormRenderStatusTaskMgr::CancelRecycleTimeout(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(serialQueueMutex_);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return false;
    }

    std::string str = std::to_string(formId);
    return serialQueue_->CancelDelayTask(str);
}
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS