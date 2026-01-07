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

#ifndef OHOS_FORM_FWK_FORM_STATE_H
#define OHOS_FORM_FWK_FORM_STATE_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "status_mgr_center/form_status_common.h"

namespace OHOS {
namespace AppExecFwk {

class FormStatus final : public DelayedRefSingleton<FormStatus> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatus)
public:
    DISALLOW_COPY_AND_MOVE(FormStatus);

    /**
     * @brief Checks if a form status exists
     * @param formId The ID of the form to check
     * @return True if the form status exists, false otherwise
     */
    bool HasFormStatus(const int64_t formId);

    /**
     * @brief Gets the form status of a form
     * @param formId The ID of the form
     * @return The form current status of the form
     */
    FormFsmStatus GetFormStatus(const int64_t formId);

    /**
     * @brief Gets the form status of a form
     * @param formId The ID of the form
     * @return The form last status of the form
     */
    FormFsmStatus GetFormLastStatus(const int64_t formId);

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
     * @brief Determines if the form process recycle.
     * @param formId The ID of the form
     * @return true if the form process recycle, false otherwise.
     */
    bool IsFormProcessRecycle(const int64_t formId);

private:
    const std::pair<FormFsmStatus, FormFsmStatus> GetFormStatusPair(const int64_t formId);
private:
    std::shared_mutex formStatusMutex_;
    // <formId, <lastStatus, curStatus>>
    std::unordered_map<int64_t, std::pair<FormFsmStatus, FormFsmStatus>> formStatusMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATE_H
