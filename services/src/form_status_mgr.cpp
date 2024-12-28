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

#include "form_status_mgr.h"
#include "form_status_queue.h"
#include "fms_log_wrapper.h"

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

void FormStatusMgr::AddFormStatus(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    if (formStatusMap_.find(formId) == formStatusMap_.end()) {
        formStatusMap_.emplace(std::make_pair(formId, FormStatus::RECOVERED));
        HILOG_INFO("formStatusMap_ insert, formId:%{public}" PRId64 ". ", formId);
    }
}

void FormStatusMgr::DeleteFormStatus(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    formStatusMap_.erase(formId);
    HILOG_INFO("formStatusMap_ erase, formId:%{public}" PRId64 ". ", formId);
}

bool FormStatusMgr::GetFormStatus(const int64_t formId, FormStatus &formStatus)
{
    FormStatus currentFormStatus;
    {
        std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
        auto iter = formStatusMap_.find(formId);
        if (iter == formStatusMap_.end()) {
            HILOG_ERROR("formStatusMap_ do not exist, formId:%{public}" PRId64 ". ", formId);
            return false;
        }
        currentFormStatus = iter->second;
    }
    formStatus = currentFormStatus;
    return true;
}

bool FormStatusMgr::SetFormStatus(const int64_t formId, FormStatus formStatus)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter == formStatusMap_.end()) {
        HILOG_ERROR("formStatusMap_ do not exist, formId:%{public}" PRId64 ". ", formId);
        return false;
    }
    iter->second = formStatus;
    return true;
}

bool FormStatusMgr::isProcessableFormStatus(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    if (formStatusMap_.find(formId) == formStatusMap_.end()) {
        HILOG_ERROR("formStatusMap_ do not exist, formId:%{public}" PRId64 ". ", formId);
        return false;
    }
    if (formStatusMap_[formId] == FormStatus::RECOVERED) {
        return true;
    } else if (formStatusMap_[formId] == FormStatus::RECYCLED) {
        return true;
    } else {
        return false;
    }
}

void FormStatusMgr::OnRenderFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECOVERED);
    FormStatusQueue::GetInstance().CancelTimeOutReAddForm(formId);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}

void FormStatusMgr::OnRecoverFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECOVERED);
    FormStatusQueue::GetInstance().CancelTimeOutReAddForm(formId);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}

void FormStatusMgr::OnRecycleFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECYCLED);
    FormStatusQueue::GetInstance().CancelTimeOutReAddForm(formId);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}
} // namespace AppExecFwk
} // namespace OHOS
