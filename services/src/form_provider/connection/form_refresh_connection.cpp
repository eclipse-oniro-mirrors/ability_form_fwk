
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_provider/connection/form_refresh_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_provider/form_supply_callback.h"
#include "form_provider/form_provider_task_mgr.h"
#include "data_center/form_data_mgr.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormRefreshConnection::FormRefreshConnection(const int64_t formId, const Want& want, const std::string &bundleName,
    const std::string &abilityName, bool isFreeInstall, const int32_t userId) : want_(want)
{
    SetFormId(formId);
    SetFreeInstall(isFreeInstall);
    SetProviderKey(bundleName, abilityName, userId);
}

/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 *
 * @param element Service ability's ElementName.
 * @param remoteObject The session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormRefreshConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("call, formId:%{public}" PRId64, GetFormId());
    FormAbilityConnection::OnAbilityConnectDone(element, remoteObject, resultCode);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
            element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }
    onFormAppConnect();
    sptr<FormRefreshConnection> connection(this);
    FormSupplyCallback::GetInstance()->AddConnection(connection);

    if (want_.HasParameter(Constants::PARAM_MESSAGE_KEY)) {
        std::string message = want_.GetStringParam(Constants::PARAM_MESSAGE_KEY);
        Want msgWant = Want(want_);
        msgWant.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
        FormProviderTaskMgr::GetInstance().PostFormEventTask(GetFormId(), message, msgWant, remoteObject);
    } else if (want_.HasParameter(Constants::RECREATE_FORM_KEY)) {
        Want cloneWant = Want(want_);
        cloneWant.RemoveParam(Constants::RECREATE_FORM_KEY);
        cloneWant.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_RECREATE_FORM);
        cloneWant.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
        FormProviderTaskMgr::GetInstance().PostAcquireTask(GetFormId(), cloneWant, remoteObject);
    } else {
        Want want = Want(want_);
        want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
        FormProviderTaskMgr::GetInstance().PostRefreshTask(GetFormId(), want, remoteObject);
        FormDataMgr::GetInstance().ClearHostRefreshFlag(GetFormId());
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS