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
#include "form_provider_stub.h"
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
FormProviderStub::FormProviderStub()
{}

FormProviderStub::~FormProviderStub()
{}
/**
 * @brief handle remote request.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_INFO("code:%{public}u, flags:%{public}d", code, option.GetFlags());
    std::u16string descriptor = FormProviderStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("localDescribe not equal to remote");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    switch (code) {
        case static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO):
            return HandleAcquireProviderFormInfo(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_DELETE):
            return HandleNotifyFormDelete(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORMS_DELETE):
            return HandleNotifyFormsDelete(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_UPDATE):
            return HandleNotifyFormUpdate(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_NOTIFY):
            return HandleEventNotify(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_TEMP_FORM_CAST):
            return HandleNotifyFormCastTempForm(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_MESSAGE):
            return HandleFireFormEvent(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_STATE_ACQUIRE):
            return HandleAcquireState(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_SHARE_FOMR_INFO):
            return HandleAcquireShareFormData(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FOMR_DATA):
            return HandleAcquireFormData(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_CONFIGURATION_UPDATE):
            return HandleNotifyConfigurationUpdate(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_LOCATION_UPDATE):
            return HandleNotifyFormLocationUpdate(data, reply);
        case static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_SIZE_CHANGED):
            return HandleNotifySizeChanged(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int FormProviderStub::HandleAcquireProviderFormInfo(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<FormJsInfo> formJsInfo(data.ReadParcelable<FormJsInfo>());
    if (!formJsInfo) {
        HILOG_ERROR("ReadParcelable<FormJsInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = AcquireProviderFormInfo(*formJsInfo, *want, client);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle NotifyFormDelete message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleNotifyFormDelete(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<FormReqInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormDelete(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle NotifyFormsDelete message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleNotifyFormsDelete(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (ret) {
        std::unique_ptr<Want> want(data.ReadParcelable<Want>());
        if (!want) {
            HILOG_ERROR("ReadParcelable<FormReqInfo> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }

        sptr<IRemoteObject> client = data.ReadRemoteObject();
        if (client == nullptr) {
            HILOG_ERROR("get remote object failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }

        int32_t result = NotifyFormsDelete(formIds, *want, client);
        reply.WriteInt32(result);
        return result;
    }

    return ERR_INVALID_DATA;
}
/**
 * @brief handle NotifyFormUpdate message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleNotifyFormUpdate(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();

    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormUpdate(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief handle EventNotify message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleEventNotify(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (ret) {
        int32_t formVisibleType;
        if (!data.ReadInt32(formVisibleType)) {
            HILOG_ERROR("read formVisibleType failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }

        std::unique_ptr<Want> want(data.ReadParcelable<Want>());
        if (!want) {
            HILOG_ERROR("ReadParcelable<Want> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }

        sptr<IRemoteObject> client = data.ReadRemoteObject();
        if (client == nullptr) {
            HILOG_ERROR("get remote object failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }

        int32_t result = EventNotify(formIds, formVisibleType, *want, client);
        reply.WriteInt32(result);
        return result;
    }

    return ERR_INVALID_DATA;
}

/**
 * @brief handle NotifyFormCastTempForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleNotifyFormCastTempForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();

    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormCastTempForm(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief handle NotifyConfigurationUpdate message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleNotifyConfigurationUpdate(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<AppExecFwk::Configuration> configuration(data.ReadParcelable<AppExecFwk::Configuration>());
    HILOG_INFO("Call.");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyConfigurationUpdate(*configuration, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief handle FireFormEvent message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleFireFormEvent(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string message = data.ReadString();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = FireFormEvent(formId, message, *want, client);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle AcquireState message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormProviderStub::HandleAcquireState(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> wantArg(data.ReadParcelable<Want>());
    if (!wantArg) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string provider = data.ReadString();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = AcquireState(*wantArg, provider, *want, client);
    reply.WriteInt32(result);
    return result;
}

int32_t FormProviderStub::HandleAcquireShareFormData(MessageParcel &data, MessageParcel &reply)
{
    auto formId = data.ReadInt64();
    auto remoteDeviceId = data.ReadString();
    auto remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto requestCode = data.ReadInt64();
    auto result = AcquireShareFormData(formId, remoteDeviceId, remoteObj, requestCode);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

int32_t FormProviderStub::HandleAcquireFormData(MessageParcel &data, MessageParcel &reply)
{
    auto formId = data.ReadInt64();
    auto remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto requestCode = data.ReadInt64();
    auto result = AcquireFormData(formId, remoteObj, requestCode);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

int32_t FormProviderStub::HandleNotifyFormLocationUpdate(MessageParcel &data, MessageParcel &reply)
{
    auto formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = NotifyFormLocationUpdate(formId, *want, remoteObj);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
 
    return ERR_OK;
}

int32_t FormProviderStub::HandleNotifySizeChanged(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call.");
    int64_t formId = data.ReadInt64();
    int32_t newDimension = data.ReadInt32();
    std::unique_ptr<Rect> newRect(data.ReadParcelable<Rect>());
    if (newRect == nullptr) {
        HILOG_ERROR("Read newRect failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto remoteObj = data.ReadRemoteObject();
    if (remoteObj == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = NotifySizeChanged(formId, newDimension, *newRect, *want, remoteObj);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS