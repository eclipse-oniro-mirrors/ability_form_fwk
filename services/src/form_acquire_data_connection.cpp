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

#include "form_acquire_data_connection.h"

#include <cinttypes>

#include "form_constants.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormAcquireDataConnection::FormAcquireDataConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName, int64_t formRequestCode) : formId_(formId), formRequestCode_(formRequestCode)
{
    SetProviderKey(bundleName, abilityName);
}

void FormAcquireDataConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_DEBUG("called.");
    if (resultCode != ERR_OK) {
        HILOG_ERROR("abilityName:%{public}s, resultCode:%{public}d",
            element.GetAbilityName().c_str(), resultCode);
        return;
    }

    FormSupplyCallback::GetInstance()->AddConnection(this);
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetParam(Constants::FORM_ACQUIRE_DATA_REQUEST_CODE, formRequestCode_);
    FormTaskMgr::GetInstance().PostAcquireDataTask(formId_, want, remoteObject);
}
} // namespace AppExecFwk
} // namespace OHOS