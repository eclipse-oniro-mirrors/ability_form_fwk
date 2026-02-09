/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_provider/connection/form_acquire_data_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_provider/form_supply_callback.h"
#include "form_provider/form_provider_task_mgr.h"
#include "common/util/form_util.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormAcquireDataConnection::FormAcquireDataConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName, int64_t formRequestCode, const int32_t userId) : formRequestCode_(formRequestCode)
{
    SetFormId(formId);
    SetProviderKey(bundleName, abilityName, userId);
}

void FormAcquireDataConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_DEBUG("call");
    if (resultCode != ERR_OK) {
        HILOG_ERROR("abilityName:%{public}s, resultCode:%{public}d",
            element.GetAbilityName().c_str(), resultCode);
        return;
    }
    onFormAppConnect();
    sptr<FormAcquireDataConnection> connection(this);
    FormSupplyCallback::GetInstance()->AddConnection(connection);
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetParam(Constants::FORM_ACQUIRE_DATA_REQUEST_CODE, formRequestCode_);
    FormProviderTaskMgr::GetInstance().PostAcquireDataTask(GetFormId(), want, remoteObject);
}
} // namespace AppExecFwk
} // namespace OHOS