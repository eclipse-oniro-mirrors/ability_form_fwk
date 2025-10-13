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

#include "form_host_proxy.h"

#include "appexecfwk_errors.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
}
void FormHostProxy::OnAcquired(const FormJsInfo &formInfo, const sptr<IRemoteObject> &token)
{
    int error;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
    }

    if (!data.WriteParcelable(&formInfo)) {
        HILOG_ERROR("write formInfo failed");
    }

    if (token != nullptr) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(token)) {
            HILOG_ERROR("flag or token write failed");
        }
    } else {
        if (!data.WriteBool(false)) {
            HILOG_ERROR("flag write failed");
        }
    }

    error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ACQUIRED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
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
        HILOG_ERROR("write interface token failed");
    }

    if (!data.WriteParcelable(&formInfo)) {
        HILOG_ERROR("write formInfo failed");
    }

    error = SendTransactCmd(IFormHost::Message::FORM_HOST_ON_UPDATE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
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
        HILOG_ERROR("write interface token failed");
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write formIds failed");
    }

    error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_UNINSTALL,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
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
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt32((int32_t) state)) {
        HILOG_ERROR("write state failed");
        return;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return;
    }

    error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_STATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnAcquireDataResponse(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteParcelable(&wantParams)) {
        HILOG_ERROR("fail write form wantParams");
        return;
    }
    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write formRequestCode failed");
        return;
    }
    int error;

    error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_DATA,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}


template<typename T>
int  FormHostProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        HILOG_ERROR("invalid size:%{public}d", infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    HILOG_INFO("get success");
    return ERR_OK;
}

bool  FormHostProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(FormHostProxy::GetDescriptor())) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    return true;
}

void FormHostProxy::OnShareFormResponse(int64_t requestCode, int32_t result)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write requestCode failed");
        return;
    }

    if (!data.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return;
    }

    int32_t error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_SHARE_FORM_RESPONSE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt32(errorCode)) {
        HILOG_ERROR("write ErrorCode failed");
        return;
    }

    if (!data.WriteString16(Str8ToStr16(errorMsg))) {
        HILOG_ERROR("fail write errorMsg");
        return;
    }

    int error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ERROR,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnError(int32_t errorCode, const std::string &errorMsg, std::vector<int64_t> &formIds)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
 
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }
 
    if (!data.WriteInt32(errorCode)) {
        HILOG_ERROR("write ErrorCode failed");
        return;
    }
 
    if (!data.WriteString16(Str8ToStr16(errorMsg))) {
        HILOG_ERROR("fail write errorMsg");
        return;
    }
 
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write formIds failed");
    }
 
    int error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ERROR_FORMS,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

int FormHostProxy::SendTransactCmd(IFormHost::Message code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("get remoteObject failed, cmd:%{public}d", code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("SendRequest failed:%{public}d,cmd:%{public}d", result, code);
        return result;
    }
    return ERR_OK;
}

void FormHostProxy::OnRecycleForm(const int64_t &formId)
{
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return;
    }

    MessageParcel reply;
    int error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_RECYCLE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnEnableForm(const std::vector<int64_t> &formIds, const bool enable)
{
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("fail write formIds");
        return;
    }

    if (!data.WriteBool(enable)) {
        HILOG_ERROR("write formId failed");
        return;
    }

    MessageParcel reply;
    int error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_ENABLE_FORM,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnLockForm(const std::vector<int64_t> &formIds, const bool lock)
{
    MessageParcel data;
    
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("fail write formIds");
        return;
    }

    if (!data.WriteBool(lock)) {
        HILOG_ERROR("write formId failed");
        return;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormHost::Message::FORM_HOST_ON_LOCK_FORM,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnDueDisableForm(const std::vector<int64_t> &formIds, const bool isDisable)
{
    HILOG_INFO("start");
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("fail write formIds");
        return;
    }

    if (!data.WriteBool(isDisable)) {
        HILOG_ERROR("write isDisable failed");
        return;
    }

    MessageParcel reply;
    int error = SendTransactCmd(IFormHost::Message::FORM_HOST_ON_DUE_DISABLE_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}

void FormHostProxy::OnDueRemoveForm(const std::vector<int64_t> &formIds, const bool isRemove)
{
    HILOG_INFO("start");
    MessageParcel data;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("fail write formIds");
        return;
    }

    if (!data.WriteBool(isRemove)) {
        HILOG_ERROR("write isRemove failed");
        return;
    }

    MessageParcel reply;
    int error = SendTransactCmd(IFormHost::Message::FORM_HOST_ON_DUE_REMOVE_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
