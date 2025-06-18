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

#ifndef OHOS_FORM_FWK_FORM_STATUS_TABLE_H
#define OHOS_FORM_FWK_FORM_STATUS_TABLE_H

#include <singleton.h>
#include <string>

#include "status_mgr_center/form_status_common.h"

namespace OHOS {
namespace AppExecFwk {
struct FormStatusMachineInfo {
    FormFsmStatus curStatus;
    FormFsmEvent event;
    FormFsmStatus nextStatus;
    FormFsmProcessType processType;
    FormEventTimeout timeoutMs;
};

class FormStatusTable final : public DelayedRefSingleton<FormStatusTable> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatusTable)
public:
    DISALLOW_COPY_AND_MOVE(FormStatusTable);

    /**
     * @brief Gets the form status information
     * @param curStatus The current form status
     * @param event The event that triggers the status change
     * @param info The form status information obtained
     * @return Whether successful or not
     */
    bool GetFormStatusInfo(FormFsmStatus curStatus, FormFsmEvent event, FormStatusMachineInfo &info);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_TABLE_H
