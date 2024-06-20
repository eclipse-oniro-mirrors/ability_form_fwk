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
#include "form_render_stub.h"
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
namespace {
    constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
}

FormRenderStub::FormRenderStub()
{
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM)] =
        &FormRenderStub::HandleRenderForm;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM)] =
        &FormRenderStub::HandleStopRenderingForm;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_FORM_HOST_DIED)] =
        &FormRenderStub::HandleCleanFormHost;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELOAD_FORM)] =
        &FormRenderStub::HandleReloadForm;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELEASE_RENDERER)] =
        &FormRenderStub::HandleReleaseRenderer;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_UNLOCKED)] =
        &FormRenderStub::HandleOnUnlock;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RECYCLE_FORM)] =
        &FormRenderStub::HandleRecycleForm;
    memberFuncMap_[static_cast<uint32_t>(IFormRender::Message::FORM_RECOVER_FORM)] =
        &FormRenderStub::HandleRecoverForm;
}

FormRenderStub::~FormRenderStub()
{
    memberFuncMap_.clear();
}

int FormRenderStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("FormRenderStub::OnReceived, code = %{public}u, flags= %{public}d.", code, option.GetFlags());
    std::u16string descriptor = FormRenderStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("%{public}s failed, local descriptor is not equal to remote", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int FormRenderStub::HandleRenderForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<FormJsInfo> formJsInfo(data.ReadParcelable<FormJsInfo>());
    if (!formJsInfo) {
        HILOG_ERROR("%{public}s, error to ReadParcelable<formJsInfo>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, error to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, error to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = RenderForm(*formJsInfo, *want, client);
    reply.WriteInt32(result);
    return result;
}

int FormRenderStub::HandleStopRenderingForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<FormJsInfo> formJsInfo(data.ReadParcelable<FormJsInfo>());
    if (!formJsInfo) {
        HILOG_ERROR("%{public}s, ReadParcelable<formJsInfo> fail", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, ReadParcelable<Want> fail", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = StopRenderingForm(*formJsInfo, *want, client);
    reply.WriteInt32(result);
    return result;
}

int FormRenderStub::HandleCleanFormHost(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> hostToken = data.ReadRemoteObject();
    if (hostToken == nullptr) {
        HILOG_ERROR("hostToken is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = CleanFormHost(hostToken);
    reply.WriteInt32(result);
    return result;
}

int32_t FormRenderStub::HandleReleaseRenderer(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string compId = data.ReadString();
    std::string uid = data.ReadString();
    int32_t result = ReleaseRenderer(formId, compId, uid);
    reply.WriteInt32(result);
    return result;
}

int FormRenderStub::HandleReloadForm(MessageParcel &data, MessageParcel &reply)
{
    std::vector<FormJsInfo> formJsInfos;
    int32_t result = GetParcelableInfos(data, formJsInfos);
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetParcelableInfos<FormJsInfo>", __func__);
        return result;
    }

    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    result = ReloadForm(std::move(formJsInfos), *want);
    reply.WriteInt32(result);
    return result;
}

int32_t FormRenderStub::HandleOnUnlock(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = OnUnlock();
    reply.WriteInt32(result);
    return result;
}

template<typename T>
int32_t FormRenderStub::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        HILOG_ERROR("%{public}s invalid size: %{public}d", __func__, infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("%{public}s, Read Parcelable infos error", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    return ERR_OK;
}

int32_t FormRenderStub::HandleRecycleForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("error to ReadParcelable<Want>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecycleForm(formId, *want);
    reply.WriteInt32(result);
    return result;
}

int32_t FormRenderStub::HandleRecoverForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("error to ReadParcelable<Want>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecoverForm(formId, *want);
    reply.WriteInt32(result);
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS
