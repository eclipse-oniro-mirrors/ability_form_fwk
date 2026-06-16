/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_MGR_HOST_ADAPTER_H
#define OHOS_FORM_FWK_FORM_MGR_HOST_ADAPTER_H

#include <singleton.h>
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
class FormMgrHostAdapter final : public DelayedRefSingleton<FormMgrHostAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormMgrHostAdapter)

public:
    DISALLOW_COPY_AND_MOVE(FormMgrHostAdapter);

    /**
     * @brief Get formIds by form location.
     * @param userId Designated User ID.
     * @param formLocation Indicate the location of the form.
     * @param formIds [out] The formIds of the form location to be returned.
     */
    void GetFormIdsByFormLocation(
        int32_t userId, Constants::FormLocation formLocation, std::vector<std::string> &formIds);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_MGR_HOST_ADAPTER_H