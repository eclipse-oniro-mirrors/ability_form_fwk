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
#include "form_render_proxy.h"

#include <utility>

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
int32_t FormRenderProxy::RenderForm(const FormJsInfo &formJsInfo, const Want &want,
    sptr<IRemoteObject> callerToken)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&formJsInfo)) {
        HILOG_ERROR("%{public}s fail, write formJsInfo error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, write want error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write callerToken error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_RENDER_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, error to SendRequest: %{public}d", __func__, error);
        return error;
    }
    return ERR_OK;
}

int32_t FormRenderProxy::StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&formJsInfo)) {
        HILOG_ERROR("%{public}s fail, write formJsInfo error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return error;
    }
    return ERR_OK;
}

int32_t FormRenderProxy::CleanFormHost(const sptr<IRemoteObject> &hostToken)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(hostToken)) {
        HILOG_ERROR("%{public}s, failed to write hostToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_FORM_HOST_DIED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return error;
    }
    return ERR_OK;
}

bool FormRenderProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(FormRenderProxy::GetDescriptor())) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return false;
    }
    return true;
}

int32_t FormRenderProxy::ReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, error to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(compId)) {
        HILOG_ERROR("%{public}s, failed to write compId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(uid)) {
        HILOG_ERROR("%{public}s, failed to write uid", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_RELEASE_RENDERER,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return error;
    }
    return ERR_OK;
}

int32_t FormRenderProxy::ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t error = WriteParcelableVector<FormJsInfo>(formJsInfos, data);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to WriteParcelableVector<FormJsInfo>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_RELOAD_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return error;
    }

    return ERR_OK;
}

int32_t FormRenderProxy::OnUnlock()
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t error = SendTransactCmd(
        IFormRender::Message::FORM_RENDER_UNLOCKED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }

    return ERR_OK;
}

int FormRenderProxy::SendTransactCmd(IFormRender::Message code, MessageParcel &data,
                                     MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("error to get remote object, cmd: %{public}d", code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("error to SendRequest: %{public}d, cmd: %{public}d", result, code);
        return result;
    }
    return ERR_OK;
}

template<typename T>
int32_t FormRenderProxy::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        HILOG_ERROR("write ParcelableVector size failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (auto &parcelable : parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            HILOG_ERROR("write ParcelableVector failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t FormRenderProxy::RecycleForm(const int64_t &formId, const Want &want)
{
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("failed to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("failed to write want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!Remote()) {
        HILOG_ERROR("Remote obj is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormRender::Message::FORM_RECYCLE_FORM),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }

    return ERR_OK;
}

int32_t FormRenderProxy::RecoverForm(const int64_t &formId, const Want &want)
{
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("failed to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("failed to write want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!Remote()) {
        HILOG_ERROR("Remote obj is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormRender::Message::FORM_RECOVER_FORM),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
