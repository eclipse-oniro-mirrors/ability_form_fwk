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

#include "form_provider/connection/form_delete_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_provider/form_supply_callback.h"
#include "status_mgr_center/form_task_mgr.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormDeleteConnection::FormDeleteConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName)
{
    SetFormId(formId);
    SetProviderKey(bundleName, abilityName);
}
/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 * @param element service ability's ElementName.
 * @param remoteObject the session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormDeleteConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("call");
    if (resultCode != ERR_OK) {
        HILOG_ERROR("abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
            element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }
    onFormAppConnect();
    sptr<FormDeleteConnection> connection(this);
    FormSupplyCallback::GetInstance()->AddConnection(connection);

    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    HILOG_DEBUG("connectId:%{public}d", this->GetConnectId());
    FormTaskMgr::GetInstance().PostDeleteTask(GetFormId(), want, remoteObject);
}
}  // namespace AppExecFwk
}  // namespace OHOS