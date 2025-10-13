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

#include "form_host_stub.h"

#include "appexecfwk_errors.h"
#include "app_scheduler_interface.h"
#include "errors.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
FormHostStub::FormHostStub()
{}

FormHostStub::~FormHostStub()
{}
/**
 * @brief handle remote request.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormHostStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("code:%{public}u,flags:%{public}d", code, option.GetFlags());
    std::u16string descriptor = FormHostStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("localDescribe not equal to remote");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    switch (code) {
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRED):
            return HandleAcquired(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UPDATE):
            return HandleOnUpdate(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UNINSTALL):
            return HandleOnUninstall(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_STATE):
            return HandleOnAcquireState(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_SHARE_FORM_RESPONSE):
            return HandleOnShareFormResponse(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ERROR):
            return HandleOnError(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_DATA):
            return HandleOnAcquireDataResponse(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_RECYCLE_FORM):
            return HandleOnRecycleForm(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ENABLE_FORM):
            return HandleOnEnableForm(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ERROR_FORMS):
            return HandleOnErrorForms(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_LOCK_FORM):
            return HandleOnLockForm(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_DUE_DISABLE_FORM):
            return HandleOnDueDisableForm(data, reply);
        case static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_DUE_REMOVE_FORM):
            return HandleOnDueRemoveForm(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
/**
 * @brief handle OnAcquired event.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormHostStub::HandleAcquired(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<FormJsInfo> formInfo(data.ReadParcelable<FormJsInfo>());
    if (!formInfo) {
        HILOG_ERROR("ReadParcelable<FormJsInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> token = nullptr;
    if (data.ReadBool()) {
        token = data.ReadRemoteObject();
    }

    OnAcquired(*formInfo, token);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}
/**
 * @brief handle OnUpdate event.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormHostStub::HandleOnUpdate(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<FormJsInfo> formInfo(data.ReadParcelable<FormJsInfo>());
    if (!formInfo) {
        HILOG_ERROR("ReadParcelable<FormJsInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    OnUpdate(*formInfo);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

/**
 * @brief handle OnUnInstall event.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormHostStub::HandleOnUninstall(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (ret) {
        OnUninstall(formIds);
        reply.WriteInt32(ERR_OK);
        return ERR_OK;
    }
    return ERR_APPEXECFWK_PARCEL_ERROR;
}

/**
 * @brief handle OnAcquireState message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormHostStub::HandleOnAcquireState(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto state = (FormState) data.ReadInt32();
    OnAcquireState(state, *want);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnShareFormResponse(MessageParcel &data, MessageParcel &reply)
{
    auto requestCode = data.ReadInt64();
    auto result = data.ReadInt32();

    OnShareFormResponse(requestCode, result);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnError(MessageParcel &data, MessageParcel &reply)
{
    int32_t errorCode = data.ReadInt32();
    std::string errorMsg = Str16ToStr8(data.ReadString16());

    OnError(errorCode, errorMsg);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnAcquireDataResponse(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOG_ERROR("ReadParcelable<wantParams> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto requestCode = data.ReadInt64();
    if (requestCode <= 0) {
        HILOG_ERROR("fail ReadInt64<requestCode>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    OnAcquireDataResponse(*wantParams, requestCode);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnRecycleForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    OnRecycleForm(formId);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnEnableForm(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("fail ReadInt64Vector<formIds>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool enable = data.ReadBool();
    OnEnableForm(formIds, enable);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnLockForm(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("fail ReadInt64Vector<formIds>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool enable = data.ReadBool();
    OnLockForm(formIds, enable);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}
 
int32_t FormHostStub::HandleOnErrorForms(MessageParcel &data, MessageParcel &reply)
{
    int32_t errorCode = data.ReadInt32();
    std::string errorMsg = Str16ToStr8(data.ReadString16());
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("fail ReadInt64Vector<formIds>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    OnError(errorCode, errorMsg, formIds);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnDueDisableForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("start");
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("fail ReadInt64Vector<formIds>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isDisable = data.ReadBool();
    OnDueDisableForm(formIds, isDisable);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}

int32_t FormHostStub::HandleOnDueRemoveForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("start");
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("fail ReadInt64Vector<formIds>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isRemove = data.ReadBool();
    OnDueRemoveForm(formIds, isRemove);
    reply.WriteInt32(ERR_OK);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS