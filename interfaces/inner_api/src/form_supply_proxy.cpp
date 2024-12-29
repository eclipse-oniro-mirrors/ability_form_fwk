/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "form_supply_proxy.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
}
/**
 * @brief Send form binding data from form provider to fms.
 * @param providerFormInfo Form binding data.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyProxy::OnAcquire(const FormProviderInfo &formInfo, const Want& want)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (want.GetIntParam(Constants::PROVIDER_FLAG, ERR_OK) == ERR_OK) {
        if (!data.WriteParcelable(&formInfo)) {
            HILOG_ERROR("write formInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_ACQUIRED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}


/**
 * @brief Send other event  to fms.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyProxy::OnEventHandle(const Want& want)
{
    MessageParcel data;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_EVENT_HANDLE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

/**
 * @brief Accept form state from form provider.
 * @param state Form state.
 * @param provider provider info.
 * @param wantArg The want of onAcquireFormState.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyProxy::OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
                                          const Want &want)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32((int32_t) state)) {
        HILOG_ERROR("write form state failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(provider)) {
        HILOG_ERROR("write providerStr failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&wantArg)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

template<typename T>
int  FormSupplyProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        HILOG_ERROR("invalid size:%{public}d", infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("fail ReadParcelable<T>");
            return ERR_INVALID_VALUE;
        }
        parcelableInfos.emplace_back(*info);
    }
    HILOG_INFO("success");
    return ERR_OK;
}

bool  FormSupplyProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(FormSupplyProxy::GetDescriptor())) {
        HILOG_ERROR("fail write interface token failed");
        return false;
    }
    return true;
}

void FormSupplyProxy::OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
    const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("fail WriteInterfaceToken");
        return;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return;
    }
    if (!data.WriteString(remoteDeviceId)) {
        HILOG_ERROR("write remoteDeviceId failed");
        return;
    }
    if (!data.WriteParcelable(&wantParams)) {
        HILOG_ERROR("write wantParams failed");
        return;
    }
    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write requestCode failed");
        return;
    }
    if (!data.WriteBool(result)) {
        HILOG_ERROR("write formResult failed");
        return;
    }
    auto error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

int FormSupplyProxy::OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("fail WriteInterfaceToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&wantParams)) {
        HILOG_ERROR("fail write form wantParams");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write formRequestCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_ACQUIRED_DATA,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRenderTaskDone(int64_t formId, const Want &want)
{
    MessageParcel data;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RENDER_TASK_DONE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnStopRenderingTaskDone(int64_t formId, const Want &want)
{
    MessageParcel data;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("error to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_STOP_RENDERING_TASK_DONE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRenderingBlock(const std::string &bundleName)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("OnRenderingBlock failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("OnRenderingBlock failed to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RENDERING_BLOCK,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int FormSupplyProxy::SendTransactCmd(IFormSupply::Message code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("get remoteObject failed, cmd:%{public}d", code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("SendRequest failed:%{public}d, cmd:%{public}d", result, code);
        return result;
    }
    return ERR_OK;
}

int32_t FormSupplyProxy::OnRecycleForm(const int64_t &formId, const Want &want)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("error to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRecoverFormsByConfigUpdate(std::vector<int64_t> &formIds)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("error to write formIds");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_BY_CONFIG_UPDATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnNotifyRefreshForm(const int64_t &formId)
{
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("error to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request.
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_NOTIFY_REFRESH,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRenderFormDone(const int64_t &formId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RENDER_FORM_DONE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRecoverFormDone(const int64_t &formId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_DONE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}

int32_t FormSupplyProxy::OnRecycleFormDone(const int64_t &formId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM_DONE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
    return error;
}
}  // namespace AppExecFwk
}  // namespace OHOS
