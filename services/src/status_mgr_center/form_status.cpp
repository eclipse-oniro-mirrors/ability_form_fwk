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

#include "status_mgr_center/form_status.h"
#include "fms_log_wrapper.h"
#include "form_status_print.h"

namespace OHOS {
namespace AppExecFwk {
FormStatus::FormStatus()
{
    HILOG_DEBUG("create FormStatus");
}

FormStatus::~FormStatus()
{
    HILOG_DEBUG("destroy FormStatus");
}

bool FormStatus::HasFormStatus(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    return !(formStatusMap_.find(formId) == formStatusMap_.end());
}

FormFsmStatus FormStatus::GetFormStatus(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter == formStatusMap_.end()) {
        HILOG_ERROR("formStatusMap_ do not exist, formId:%{public}" PRId64, formId);
        return FormFsmStatus::INIT;
    }

    return iter->second;
}

void FormStatus::SetFormStatus(const int64_t formId, FormFsmStatus formStatus)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter == formStatusMap_.end()) {
        HILOG_INFO("set new form status, formId:%{public}" PRId64 ", status is %{public}d.",
            formId,
            static_cast<int32_t>(formStatus));
        formStatusMap_.emplace(formId, formStatus);
        return;
    }

    iter->second = formStatus;
    HILOG_DEBUG(
        "set form status, formId:%{public}" PRId64 ", status is %{public}d.", formId, static_cast<int32_t>(formStatus));
}

void FormStatus::DeleteFormStatus(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter != formStatusMap_.end()) {
        HILOG_INFO("delete form status, formId:%{public}" PRId64, formId);
        formStatusMap_.erase(iter);
    } else {
        HILOG_INFO("not find formId:%{public}" PRId64, formId);
    }
}

bool FormStatus::IsFormProcessRecycle(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter == formStatusMap_.end()) {
        HILOG_DEBUG("formStatusMap_ do not exist, formId:%{public}" PRId64, formId);
        return false;
    }
    HILOG_INFO("formId:%{public}" PRId64 ", curStatus:%{public}s",
        formId,
        FormStatusPrint::FormStatusToString(iter->second).c_str());

    return iter->second == FormFsmStatus::RECYCLED || iter->second == FormFsmStatus::RECYCLING_DATA ||
           iter->second == FormFsmStatus::RECYCLING;
}
}  // namespace AppExecFwk
}  // namespace OHOS
