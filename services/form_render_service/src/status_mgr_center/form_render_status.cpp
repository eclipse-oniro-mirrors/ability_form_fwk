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

#include "status_mgr_center/form_render_status.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormRenderStatus::FormRenderStatus()
{
    HILOG_DEBUG("create FormRenderStatus");
}

FormRenderStatus::~FormRenderStatus()
{
    HILOG_DEBUG("destroy FormRenderStatus");
}

bool FormRenderStatus::HasFormStatus(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    return !(formStatusMap_.find(formId) == formStatusMap_.end());
}

FormFsmStatus FormRenderStatus::GetFormStatus(const int64_t formId)
{
    std::shared_lock<std::shared_mutex> lock(formStatusMutex_);
    auto iter = formStatusMap_.find(formId);
    if (iter == formStatusMap_.end()) {
        HILOG_ERROR("formStatusMap_ do not exist, formId:%{public}" PRId64, formId);
        return FormFsmStatus::UNPROCESSABLE;
    }

    return iter->second;
}

void FormRenderStatus::SetFormStatus(const int64_t formId, FormFsmStatus formStatus)
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
    HILOG_INFO(
        "set form status, formId:%{public}" PRId64 ", status is %{public}d.", formId, static_cast<int32_t>(formStatus));
}

void FormRenderStatus::DeleteFormStatus(const int64_t formId)
{
    std::unique_lock<std::shared_mutex> lock(formStatusMutex_);
    HILOG_INFO("formId:%{public}" PRId64, formId);
    auto iter = formStatusMap_.find(formId);
    if (iter != formStatusMap_.end()) {
        formStatusMap_.erase(iter);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
