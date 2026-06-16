/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "feature/form_share/form_share_connection.h"

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "feature/form_share/form_share_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormShareConnection::FormShareConnection(int64_t formId, const std::string &bundleName,
    const std::string &abilityName, const std::string &deviceId, int64_t formShareRequestCode,
    const int32_t userId)
    : formId_(formId), remoteDeviceId_(deviceId), formShareRequestCode_(formShareRequestCode)
{
    SetProviderKey(bundleName, abilityName, userId);
}

void FormShareConnection::OnConnectError(int resultCode, const AppExecFwk::ElementName &element)
{
    FormShareTaskMgr::GetInstance().PostFormShareSendResponse(
        formShareRequestCode_, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
}

Want FormShareConnection::OnBuildTaskWant()
{
    Want want = FormAbilityConnection::OnBuildTaskWant();
    want.SetParam(Constants::FORM_SHARE_REQUEST_CODE, formShareRequestCode_);
    return want;
}

void FormShareConnection::OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    FormShareTaskMgr::GetInstance().PostShareAcquireTask(formId_, remoteDeviceId_, want, remoteObject);
}

} // namespace AppExecFwk
} // namespace OHOS