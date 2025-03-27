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

#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_status_queue.h"
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

void FormStatusMgr::AddFormStatus(const int64_t formId, FormStatus formStatus)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    formStatusMap_[formId] = formStatus;
    HILOG_INFO("AddFormStatus formId:%{public}" PRId64 ", formStatus is %{public}d.", formId, (int)formStatus);
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
    HILOG_INFO("GetFormStatus formId:%{public}" PRId64 ", formStatus is %{public}d.", formId, (int)formStatus);
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
    HILOG_INFO("SetFormStatus formId:%{public}" PRId64 ", formStatus is %{public}d.", formId, (int)formStatus);
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

void FormStatusMgr::ResetFormStatus(const int64_t &formId)
{
    if (isProcessableFormStatus(formId)) {
        return;
    }
    HILOG_INFO("Reset formId:%{public}" PRId64 " status.", formId);
    SetFormStatus(formId, FormStatus::RECOVERED);
}

void FormStatusMgr::OnRenderFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECOVERED);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}

void FormStatusMgr::OnRecoverFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECOVERED);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}

void FormStatusMgr::OnRecycleFormDone(const int64_t &formId)
{
    SetFormStatus(formId, FormStatus::RECYCLED);
    FormStatusQueue::GetInstance().PostFormCommandTaskByFormId(formId);
}
} // namespace AppExecFwk
} // namespace OHOS
