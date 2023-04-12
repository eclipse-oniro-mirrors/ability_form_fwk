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

#include "form_background_connection.h"

#include "form_constants.h"
#include "form_mgr_proxy.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "hilog_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormBackgroundConnection::FormBackgroundConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName, const std::string &funcName, const std::string &params)
     : formId_(formId), funcName_(funcName), params_(params)
{
    SetProviderKey(bundleName, abilityName);
}
/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 * @param element service ability's ElementName.
 * @param remoteObject the session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormBackgroundConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_DEBUG("called.");
    if (resultCode != ERR_OK) {
        HILOG_ERROR("%{public}s, abilityName:%{public}s, resultCode:%{public}d",
            __func__, element.GetAbilityName().c_str(), resultCode);
        return;
    }
    HILOG_DEBUG("%{public}lld formId.", (long long)formId_);
    sptr<IFormMgr> formMgrProxy = iface_cast<IFormMgr>(remoteObject);
    if (formMgrProxy == nullptr) {
        HILOG_ERROR("Failed to get formMgrProxy");
        return;
    }
    formMgrProxy->SetBackgroundFunction(funcName_, params_);
    FormSupplyCallback::GetInstance()->RemoveConnection(this->GetConnectId());
    HILOG_DEBUG("end.");
}
}  // namespace AppExecFwk
}  // namespace OHOS