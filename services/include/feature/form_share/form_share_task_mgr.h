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

#ifndef OHOS_FORM_FWK_FORM_SHARE_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_SHARE_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class FormShareTaskMgr final : public DelayedRefSingleton<FormShareTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormShareTaskMgr)

public:
    /**
     * @brief Acquire share form data from form provider(task).
     * @param formId The Id of the form.
     * @param remoteDeviceId The device ID to share.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostShareAcquireTask(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post form share error code to form host(task).
    * @param formShareRequestCode The request code for this share.
    * @param result The error code of this share.
    */
    void PostFormShareSendResponse(int64_t formShareRequestCode, int32_t result);

private:
    /**
     * @brief Acquire share form data from form provider(task).
     * @param formId The Id of the form.
     * @param remoteDeviceId The device ID to share.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post form share error code to form host(task).
    * @param formShareRequestCode The request code for this share.
    * @param result The error code of this share.
    */
    void FormShareSendResponse(int64_t formShareRequestCode, int32_t result);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SHARE_TASK_MGR_H