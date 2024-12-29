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

#ifndef OHOS_FORM_FWK_FORM_STATUS_MGR_H
#define OHOS_FORM_FWK_FORM_STATUS_MGR_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
enum class FormStatus {
    UNPROCESSABLE,
    RECOVERED,
    RECOVERING,
    RECYCLED,
    RECYCLING,
};

class FormStatusMgr final : public DelayedRefSingleton<FormStatusMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormStatusMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormStatusMgr);
public:
    void AddFormStatus(const int64_t formId);
    void DeleteFormStatus(const int64_t formId);

    bool GetFormStatus(const int64_t formId, FormStatus &formStatus);
    bool SetFormStatus(const int64_t formId, FormStatus formStatus);

    bool isProcessableFormStatus(const int64_t formId);
    
    /*
     * @brief Send render form message to form_status_mgr.
     * @param formIds The Id list of forms.
     * @param want The want of forms to be recycled.
     */
    void OnRenderFormDone(const int64_t &formId);

    /**
     * @brief Send recover form message to form_status_mgr.
     * @param formIds The Id list of forms.
     * @param want The want of forms to be recycled.
     */
    void OnRecoverFormDone(const int64_t &formId);
    
    /**
     * @brief Send recycle form message to form_status_mgr.
     * @param formIds The Id list of forms.
     * @param want The want of forms to be recycled.
     */
    void OnRecycleFormDone(const int64_t &formId);

private:
    // <formId, formStatus>
    std::shared_mutex formStatusMutex_;
    std::unordered_map<int64_t, FormStatus> formStatusMap_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_STATUS_MGR_H
