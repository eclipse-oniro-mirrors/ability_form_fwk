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

#include "form_host_proxy.h"

#include "appexecfwk_errors.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Request to give back a Form.
 * @param formInfo Form info.
 */
void FormHostProxy::OnAcquired(const FormJsInfo &formInfo)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
    }

    if (!data.WriteParcelable(&formInfo)) {
        HILOG_ERROR("%{public}s, failed to write formInfo", __func__);
    }

    error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRED),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
    }
}


/**
* @brief Form is updated.
* @param bundleName Provider ability bundleName.
*/
void FormHostProxy::OnUpdate(const FormJsInfo &formInfo)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
    }

    if (!data.WriteParcelable(&formInfo)) {
        HILOG_ERROR("%{public}s, failed to write formInfo", __func__);
    }

    error = Remote()->SendRequest(static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UPDATE), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
    }
}


/**
 * @brief Form provider is uninstalled
 * @param formIds The Id list of the forms.
 */
void  FormHostProxy::OnUninstall(const std::vector<int64_t> &formIds)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write formIds", __func__);
    }

    error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UNINSTALL),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
    }
}

/**
 * @brief Form provider is acquire state
 * @param state The form state.
 * @param want The form want.
 */
void FormHostProxy::OnAcquireState(FormState state, const AAFwk::Want &want)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return;
    }

    if (!data.WriteInt32((int32_t) state)) {
        HILOG_ERROR("%{public}s, failed to write state", __func__);
        return;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return;
    }

    error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_STATE),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
    }
}


template<typename T>
int  FormHostProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("%{public}s, failed to read Parcelable infos", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    HILOG_INFO("%{public}s, get parcelable infos success", __func__);
    return ERR_OK;
}

bool  FormHostProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(FormHostProxy::GetDescriptor())) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
