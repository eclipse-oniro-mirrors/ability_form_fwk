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

#ifndef OHOS_FORM_FWK_FORM_RENDER_STATE_H
#define OHOS_FORM_FWK_FORM_RENDER_STATE_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "util/form_status_common.h"
#include "status_mgr_center/form_render_status_table.h"

namespace OHOS {
namespace AppExecFwk {

class FormRenderStatus final : public DelayedRefSingleton<FormRenderStatus> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderStatus)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderStatus);

    /**
     * @brief Checks if a form status exists
     * @param formId The ID of the form to check
     * @return True if the form status exists, false otherwise
     */
    bool HasFormStatus(const int64_t formId);

    /**
     * @brief Gets the form status of a form
     * @param formId The ID of the form
     * @return The form status of the form
     */
    FormFsmStatus GetFormStatus(const int64_t formId);

    /**
     * @brief Sets the form status of a form
     * @param formId The ID of the form
     * @param formStatus The form status to set
     */
    void SetFormStatus(const int64_t formId, FormFsmStatus formStatus);

    /**
     * @brief Deletes the form status of a form
     * @param formId The ID of the form
     */
    void DeleteFormStatus(const int64_t formId);

    /**
     * @brief Atomically transitions the form status: find-or-create (INIT), look up the
     * FSM table and apply nextStatus all under one exclusive lock, so concurrent
     * PostFormEvent calls cannot interleave read-check-set.
     * @param formId The ID of the form
     * @param event The event that triggers the status change
     * @param info The matched FSM info (curStatus/nextStatus/processType) on success
     * @return True if the transition was applied, false if the FSM table has no entry
     */
    bool TransitionFormStatus(const int64_t formId, const FormFsmEvent event, FormRenderStatusMachineInfo &info);

private:
    // <formId, formStatus>
    std::shared_mutex formStatusMutex_;
    std::unordered_map<int64_t, FormFsmStatus> formStatusMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_STATE_H
