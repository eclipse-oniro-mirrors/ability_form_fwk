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
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
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

    int32_t error = SendTransactCmd(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM,
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

    int32_t error = SendTransactCmd(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_REMOVE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
    }
    return error;
}

int32_t JsFormStateObserverProxy::NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType formVisiblityType,
    const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &formInstances)
{
    HILOG_DEBUG("called.");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(AbilityRuntime::IJsFormStateObserver::GetDescriptor())) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t formVisiblityTypeInt = static_cast<int32_t>(formVisiblityType);
    if (!data.WriteInt32(formVisiblityTypeInt)) {
        HILOG_ERROR("failed to write formVisiblityType");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write formVisiblityType");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    HILOG_DEBUG("NotifyWhetherFormsVisible formInstances size %{public}zu size", formInstances.size());
    if (!data.WriteInt32(formInstances.size())) {
        HILOG_ERROR("write int32 failed");
        return false;
    }
    for (auto &parcelable: formInstances) {
        if (!data.WriteParcelable(&parcelable)) {
            HILOG_ERROR("write parcelable failed");
            return false;
        }
    }
    int32_t error = SendTransactCmd(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to get form instances by filter: %{public}d", error);
    }

    return error;
}

int JsFormStateObserverProxy::SendTransactCmd(IJsFormStateObserver::Message code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("%{public}s, failed to get remote object, cmd: %{public}d", __func__, code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d, cmd: %{public}d", __func__, result, code);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return ERR_OK;
}

int32_t JsFormStateObserverProxy::OnFormClickEvent(
    const std::string &bundleName, const std::string &callType, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(AbilityRuntime::IJsFormStateObserver::GetDescriptor())) {
        HILOG_ERROR("Failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("Failed to write bundle name.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(callType)) {
        HILOG_ERROR("failed to write call type");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&runningFormInfo)) {
        HILOG_ERROR("failed to write runningFormInfo");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("Failed to get remote object");
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_FORM_CLICK), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
    }
    return error;
}
} // namespace AbilityRuntime
} // namespace OHOS
