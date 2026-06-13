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

#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_provider/form_provider_task_mgr.h"
#include "form_provider/form_supply_callback.h"

namespace OHOS {
namespace AppExecFwk {

FormRefreshConnection::FormRefreshConnection(const int64_t formId, const Want &want, const FormRecord &record)
    : want_(want), record_(record)
{
    SetFormId(formId);
    SetFreeInstall(record.needFreeInstall);
    SetProviderKey(record.bundleName, record.abilityName, record.providerUserId);
    SetModuleName(record.moduleName);
}

sptr<FormAbilityConnection> FormRefreshConnection::CreateRetryConnection() const
{
    sptr<FormRefreshConnection> retryConnection = new FormRefreshConnection(GetFormId(), want_, record_);
    return retryConnection;
}

Want FormRefreshConnection::OnBuildTaskWant()
{
    if (want_.HasParameter(Constants::PARAM_MESSAGE_KEY)) {
        Want msgWant = Want(want_);
        msgWant.SetParam(Constants::FORM_CONNECT_ID, GetConnectId());
        return msgWant;
    } else if (want_.HasParameter(Constants::RECREATE_FORM_KEY)) {
        Want cloneWant = Want(want_);
        cloneWant.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_RECREATE_FORM);
        cloneWant.SetParam(Constants::FORM_CONNECT_ID, GetConnectId());
        return cloneWant;
    }
    Want refreshWant = Want(want_);
    refreshWant.SetParam(Constants::FORM_CONNECT_ID, GetConnectId());
    return refreshWant;
}

void FormRefreshConnection::OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    SetProviderToken(remoteObject);
    if (want.HasParameter(Constants::PARAM_MESSAGE_KEY)) {
        std::string message = want.GetStringParam(Constants::PARAM_MESSAGE_KEY);
        FormProviderTaskMgr::GetInstance().PostFormEventTask(GetFormId(), message, want, remoteObject);
    } else if (want.HasParameter(Constants::RECREATE_FORM_KEY)) {
        FormProviderTaskMgr::GetInstance().PostAcquireTask(GetFormId(), want, remoteObject);
    } else {
        FormProviderTaskMgr::GetInstance().PostRefreshTask(GetFormId(), want, remoteObject);
        FormDataMgr::GetInstance().ClearHostRefreshFlag(GetFormId());
    }
}

void FormRefreshConnection::OnPreConnectTask()
{
    connectState_.store(ConnectState::CONNECTED);
}

void FormRefreshConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int resultCode)
{
    ConnectState state = connectState_.load();
    HILOG_INFO("formId:%{public}" PRId64 ", resultCode:%{public}d, connectState:%{public}d",
        GetFormId(), resultCode, static_cast<int32_t>(state));

    FormAbilityConnection::OnAbilityDisconnectDone(element, resultCode);

    if (resultCode == DISCONNECT_ERROR && state == ConnectState::CONNECTED) {
        sptr<FormAbilityConnection> connection = this;
        FormProviderErrorHandlerFactory::GetRefreshHandler()
            ->HandleDisconnectError(GetFormId(), connection);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS