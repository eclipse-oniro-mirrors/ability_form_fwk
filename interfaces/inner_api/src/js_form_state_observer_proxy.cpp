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

#include "js_form_state_observer_proxy.h"

#include "appexecfwk_errors.h"
#include "hilog_wrapper.h"
#include "ipc_types.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t JsFormStateObserverProxy::OnAddForm(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(AbilityRuntime::IJsFormStateObserver::GetDescriptor())) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&runningFormInfo)) {
        HILOG_ERROR("failed to write runningFormInfo");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
    }
    return error;
}

int32_t JsFormStateObserverProxy::OnRemoveForm(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(AbilityRuntime::IJsFormStateObserver::GetDescriptor())) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&runningFormInfo)) {
        HILOG_ERROR("failed to write runningFormInfo");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_REMOVE_FORM),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
    }
    return error;
}
} // namespace AbilityRuntime
} // namespace OHOS
