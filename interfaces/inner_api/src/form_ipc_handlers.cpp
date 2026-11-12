/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_ipc_handlers.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_info.h"
#include "form_mgr_errors.h"
#include "peer_form_service_info.h"
#include "running_form_info.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include <vector>

namespace OHOS {
namespace AppExecFwk {

const int32_t LIMIT_PARCEL_SIZE = 1024;
constexpr size_t MAX_PARCEL_CAPACITY = 4 * 1024 * 1024;
static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;

void SplitString(const std::string &source, std::vector<std::string> &strings)
{
    size_t splitSize = (source.size() / LIMIT_PARCEL_SIZE);
    if ((source.size() % LIMIT_PARCEL_SIZE) != 0) {
        splitSize++;
    }
    HILOG_DEBUG("the dump string split into %{public}zu size", splitSize);
    for (size_t i = 0; i < splitSize; i++) {
        size_t start = LIMIT_PARCEL_SIZE * i;
        strings.emplace_back(source.substr(start, LIMIT_PARCEL_SIZE));
    }
}

/**
 * @brief Write a parcelabe vector objects to the proxy node.
 * @param parcelableVector Indicates the objects to be write.
 * @param reply Indicates the reply to be sent;
 * @return Returns true if objects send successfully; returns false otherwise.
 */
template<typename T>
bool WriteParcelableVector(std::vector<T> &parcelableVector, Parcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        HILOG_ERROR("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable: parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            HILOG_ERROR("write ParcelableVector failed");
            return false;
        }
    }
    return true;
}

bool ReadFormDataProxies(MessageParcel &data, std::vector<FormDataProxy> &formDataProxies)
{
    int32_t number = 0;
    if (!data.ReadInt32(number)) {
        HILOG_ERROR("read proxies number failed");
        return false;
    }
    HILOG_DEBUG("proxies number:%{public}d", number);
    if (number < 0 || number > INT16_MAX) {
        HILOG_ERROR("proxies number over limit:%{public}d", number);
        return false;
    }

    for (int32_t i = 0; i < number; i++) {
        std::u16string keyStr;
        if (!data.ReadString16(keyStr)) {
            HILOG_ERROR("read key failed");
            return false;
        }
        std::u16string subscribeIdStr;
        if (!data.ReadString16(subscribeIdStr)) {
            HILOG_ERROR("read subscribeId failed");
            return false;
        }
        std::string key = Str16ToStr8(keyStr);
        std::string subscribeId = Str16ToStr8(subscribeIdStr);
        if (key.empty()) {
            continue;
        }
        FormDataProxy formDataProxy(key, subscribeId);
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

static LockChangeType ParseLockChangeType(int32_t value)
{
    switch (value) {
        case static_cast<int32_t>(LockChangeType::SWITCH_CHANGE):
            return LockChangeType::SWITCH_CHANGE;
        case static_cast<int32_t>(LockChangeType::PROTECT_CHANGE):
            return LockChangeType::PROTECT_CHANGE;
        default:
            HILOG_ERROR("lockChangeType invalid");
            return LockChangeType::INVALID_PARAMETER;
    }
}

namespace FormIpcHandlers {

/**
 * @brief handle AddForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleAddForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("read want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("RemoteObject invalidate");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    FormJsInfo formJsInfo;
    int32_t result = svc.AddForm(formId, *want, client, formJsInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteParcelable(&formJsInfo)) {
        HILOG_ERROR("write formJsInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return result;
}

/**
 * @brief handle CreateForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleCreateForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("fail ReadParcelable");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    RunningFormInfo runningFormInfo;
    int32_t result = svc.CreateForm(*want, runningFormInfo);
    reply.WriteInt32(result);
    reply.WriteParcelable(&runningFormInfo);
    return result;
}

/**
 * @brief handle DeleteForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDeleteForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("read client failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.DeleteForm(formId, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle DeleteFormByCompId message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleStopRenderingForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string compId;
    if (!data.ReadString(compId)) {
        HILOG_ERROR("read compId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.StopRenderingForm(formId, compId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle ReleaseForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleReleaseForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("read client failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool delCache = false;
    if (!data.ReadBool(delCache)) {
        HILOG_ERROR("read delCache failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.ReleaseForm(formId, client, delCache);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle UpdateForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleUpdateForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<FormProviderData> formBindingData(data.ReadParcelable<FormProviderData>());
    if (formBindingData == nullptr) {
        HILOG_ERROR("fail get formBindingData");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.UpdateForm(formId, *formBindingData);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleUpdateFormProviderInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<FormProviderInfo> formProviderInfo(data.ReadParcelable<FormProviderInfo>());
    if (formProviderInfo == nullptr) {
        HILOG_ERROR("fail get formProviderInfo");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.UpdateForm(formId, *formProviderInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle UpdateFormCrossBundle message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleUpdateFormCrossBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<FormProviderData> formBindingData(data.ReadParcelable<FormProviderData>());
    if (formBindingData == nullptr) {
        HILOG_ERROR("fail get formBindingData");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.UpdateFormCrossBundle(formId, *formBindingData);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

/**
     * @brief handle SetNextRefreshTime message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
int32_t HandleSetNextRefreshTime(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t nextTime = 0;
    if (!data.ReadInt64(nextTime)) {
        HILOG_ERROR("read nextTime failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.SetNextRefreshTime(formId, nextTime);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle ReleaseRenderer message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleReleaseRenderer(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string compId;
    if (!data.ReadString(compId)) {
        HILOG_ERROR("read compId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.ReleaseRenderer(formId, compId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle RequestPublishFormCrossUser message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleRequestPublishFormCrossUser(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t userId;
    if (!data.ReadInt32(userId)) {
        HILOG_ERROR("get userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int64_t formId = 0;
    ErrCode result = svc.RequestPublishFormCrossUser(*want, userId, formId);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        reply.WriteInt64(formId);
    }
    return result;
}

/**
 * @brief handle RequestPublishForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleRequestPublishForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    if (withFormBindingData) {
        formProviderData.reset(data.ReadParcelable<FormProviderData>());
        if (formProviderData == nullptr) {
            HILOG_ERROR("get formProviderData failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    int64_t formId = 0;
    ErrCode result = svc.RequestPublishForm(*want, withFormBindingData, formProviderData, formId);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        reply.WriteInt64(formId);
    }
    return result;
}

int32_t HandleSetPublishFormResult(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string message;
    if (!data.ReadString(message)) {
        HILOG_ERROR("read message failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (message.size() > static_cast<size_t>(Constants::MAX_PUBLISH_FORM_MESSAGE_LENGTH)) {
        HILOG_ERROR("message length %{public}zu exceeds limit %{public}d",
            message.size(), Constants::MAX_PUBLISH_FORM_MESSAGE_LENGTH);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.message = message;
    int32_t err = 0;
    if (!data.ReadInt32(err)) {
        HILOG_ERROR("read err failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (err < static_cast<int32_t>(Constants::PublishFormErrorCode::SUCCESS) ||
        err >= static_cast<int32_t>(Constants::PublishFormErrorCode::BUTT)) {
        HILOG_ERROR("invalid PublishFormErrorCode:%{public}d", err);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    errorCodeInfo.code = static_cast<Constants::PublishFormErrorCode>(err);
    ErrCode result = svc.SetPublishFormResult(formId, errorCodeInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleAcquireAddFormResult(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.AcquireAddFormResult(formId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle LifecycleUpdate message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleLifecycleUpdate(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool updateType = false;
    if (!data.ReadBool(updateType)) {
        HILOG_ERROR("read updateType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.LifecycleUpdate(formIds, client, updateType);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle RequestForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleRequestForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");

    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.RequestForm(formId, client, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle NotifyVisibleForms message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleNotifyWhetherVisibleForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("read client failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t formVisibleType = 0;
    if (!data.ReadInt32(formVisibleType)) {
        HILOG_ERROR("read formVisibleType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.NotifyWhetherVisibleForms(formIds, client, formVisibleType);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle HasFormVisible message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleHasFormVisible(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    uint32_t tokenId = 0;
    if (!data.ReadUint32(tokenId)) {
        HILOG_ERROR("read tokenId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = svc.HasFormVisible(tokenId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

/**
 * @brief handle CastTempForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleCastTempForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("read client failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.CastTempForm(formId, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle DumpStorageFormInfos message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDumpStorageFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::string formInfos;
    int32_t result = svc.DumpStorageFormInfos(formInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(formInfos, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("WriteStringVector<dumpInfos> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    return result;
}

/**
 * @brief Handle DumpFormInfoByBundleName message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDumpFormInfoByBundleName(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    std::string formInfos;
    int32_t result = svc.DumpFormInfoByBundleName(bundleName, formInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        HILOG_DEBUG("formInfos:%{public}s", formInfos.c_str());
        std::vector<std::string> dumpInfos;
        SplitString(formInfos, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("WriteStringVector<dumpInfos> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    return result;
}

/**
 * @brief Handle DumpFormInfoByFormId message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDumpFormInfoByFormId(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string formInfo;
    int32_t result = svc.DumpFormInfoByFormId(formId, formInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(formInfo, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("WriteStringVector<dumpInfos> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle DumpFormTimerByFormId message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDumpFormTimerByFormId(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string isTimingService;
    int32_t result = svc.DumpFormTimerByFormId(formId, isTimingService);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(isTimingService, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("WriteStringVector<dumpInfos> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle DumpFormInfoByFormId message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleMessageEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
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
    int32_t result = svc.MessageEvent(formId, *want, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle RouterEvent message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleRouterEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
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
    int32_t result = svc.RouterEvent(formId, *want, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle Background message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleBackgroundEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
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
    int32_t result = svc.BackgroundEvent(formId, *want, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle InsightIntentEvent message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleInsightIntentEvent(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
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
    int32_t result = svc.InsightIntentEvent(formId, *want, client);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle DeleteInvalidForms message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleDeleteInvalidForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t numFormsDeleted = 0;
    int32_t result = svc.DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(numFormsDeleted)) {
        HILOG_ERROR("fail write numFormsDeleted");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle AcquireFormState message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleAcquireFormState(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    FormStateInfo stateInfo {};
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("ReadParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.AcquireFormState(*want, callerToken, stateInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(stateInfo.state))) {
        HILOG_ERROR("write state failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle NotifyFormsVisible message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleNotifyFormsVisible(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    bool isVisible = false;
    if (!data.ReadBool(isVisible)) {
        HILOG_ERROR("ReadBool failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = svc.NotifyFormsVisible(formIds, isVisible, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleNotifyFormsPrivacyProtected(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    bool isProtected = false;
    if (!data.ReadBool(isProtected)) {
        HILOG_ERROR("ReadBool failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = svc.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle NotifyFormsEnableUpdate message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleNotifyFormsEnableUpdate(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    bool isEnableUpdate = false;
    if (!data.ReadBool(isEnableUpdate)) {
        HILOG_ERROR("ReadBool failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = svc.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief Handle GetAllFormsInfo message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetAllFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("max parcel capacity:%{public}zu", MAX_PARCEL_CAPACITY);
    std::vector<FormInfo> infos;
    int32_t result = svc.GetAllFormsInfo(infos);
    (void)reply.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle GetAllTemplateFormsInfo message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetAllTemplateFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("max parcel capacity:%{public}zu", MAX_PARCEL_CAPACITY);
    std::vector<FormInfo> infos;
    int32_t result = svc.GetAllTemplateFormsInfo(infos);
    (void)reply.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle GetFormsInfoByApp message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetFormsInfoByApp(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = svc.GetFormsInfoByApp(bundleName, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle GetTemplateFormsInfoByApp message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetTemplateFormsInfoByApp(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = svc.GetTemplateFormsInfoByApp(bundleName, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle GetFormsInfoByModule message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetFormsInfoByModule(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = svc.GetFormsInfoByModule(bundleName, moduleName, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

/**
 * @brief Handle GetTemplateFormsInfoByModule message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleGetTemplateFormsInfoByModule(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = svc.GetTemplateFormsInfoByModule(bundleName, moduleName, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t HandleGetFormsInfoByFilter(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    FormInfoFilter filter;
    if (!data.ReadString(filter.bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.ReadString(filter.moduleName)) {
        HILOG_ERROR("read moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.ReadInt32Vector(&filter.supportDimensions)) {
        HILOG_ERROR("read supportDimensions failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (filter.supportDimensions.size() > Constants::MAX_LAYOUT) {
        HILOG_ERROR("supportDimensions size %{public}zu exceeds limit %{public}zu",
            filter.supportDimensions.size(), Constants::MAX_LAYOUT);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (!data.ReadInt32Vector(&filter.supportShapes)) {
        HILOG_ERROR("read supportShapes failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (filter.supportShapes.size() > Constants::MAX_LAYOUT) {
        HILOG_ERROR("supportShapes size %{public}zu exceeds limit %{public}zu",
            filter.supportShapes.size(), Constants::MAX_LAYOUT);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormInfo> infos;
    int32_t result = svc.GetFormsInfoByFilter(filter, infos);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK && !WriteParcelableVector(infos, reply)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleGetFormsInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<FormInfoFilter> filter(data.ReadParcelable<FormInfoFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("fail get filter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormInfo> infos;
    int32_t result = svc.GetFormsInfo(*filter, infos);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t HandleGetPublishedFormInfoById(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    RunningFormInfo info;
    int32_t result = svc.GetPublishedFormInfoById(formId, info);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK && !reply.WriteParcelable(&info)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleGetPublishedFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<RunningFormInfo> infos;
    int32_t result = svc.GetPublishedFormInfos(infos);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK && !WriteParcelableVector(infos, reply)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleShareForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string deviceId;
    if (!data.ReadString(deviceId)) {
        HILOG_ERROR("read deviceId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t requestCode = 0;
    if (!data.ReadInt64(requestCode)) {
        HILOG_ERROR("read requestCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto result = svc.ShareForm(formId, deviceId, callerToken, requestCode);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleAcquireFormData(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t requestCode = 0;
    if (!data.ReadInt64(requestCode)) {
        HILOG_ERROR("read requestCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    AAFwk::WantParams customizeData;
    int32_t result = svc.AcquireFormData(formId, requestCode, callerToken, customizeData);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteParcelable(&customizeData)) {
            HILOG_ERROR("write customizeData failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        HILOG_INFO("skip writing customizeData, result:%{public}d", result);
    }
    return result;
}

int32_t HandleRecvFormShareInfoFromRemote(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormShareInfo> info(data.ReadParcelable<FormShareInfo>());
    if (!info) {
        HILOG_ERROR("fail ReadParcelable<FormShareInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RecvFormShareInfoFromRemote(*info);
    reply.WriteInt32(result);
    return result;
}

int32_t HandleIsRequestPublishFormSupported(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    bool result = svc.IsRequestPublishFormSupported();
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleStartAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.StartAbility(*want, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleStartAbilityByFms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.StartAbilityByFms(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleStartUIAbilityByFms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.StartUIAbilityByFms(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleStartAbilityByCrossBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    int32_t result = svc.StartAbilityByCrossBundle(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    return result;
}

int32_t HandleCheckFMSReady(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int32_t result = svc.CheckFMSReady();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleIsSystemAppForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    bool result = svc.IsSystemAppForm(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterFormAddObserverByBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");

    std::string bundleName = data.ReadString();
    if (bundleName.size() > Constants::MAX_BUNDLE_NAME_LENGTH) {
        HILOG_ERROR("bundleName too long: %{public}zu", bundleName.size());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RegisterFormAddObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t HandleRegisterFormRemoveObserverByBundle(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");

    std::string bundleName = data.ReadString();
    if (bundleName.size() > Constants::MAX_BUNDLE_NAME_LENGTH) {
        HILOG_ERROR("bundleName too long: %{public}zu", bundleName.size());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t HandleGetFormsCount(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    bool isTempFormFlag = false;
    if (!data.ReadBool(isTempFormFlag)) {
        HILOG_ERROR("fail read temp flag");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t formCount = 0;
    int32_t result = svc.GetFormsCount(isTempFormFlag, formCount);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(formCount)) {
        HILOG_ERROR("write formCount failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleGetFormInstancesByFilter(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormInstancesFilter> filter(data.ReadParcelable<FormInstancesFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("fail get filter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormInstance> infos;
    auto result = svc.GetFormInstancesByFilter(*filter, infos);
    HILOG_DEBUG("info size = %{public}zu", infos.size());
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        HILOG_INFO("result is ok");
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t HandleGetFormInstanceById(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isUnusedInclude = false;
    if (!data.ReadBool(isUnusedInclude)) {
        HILOG_ERROR("read isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    FormInstance info;
    auto result = svc.GetFormInstanceById(formId, isUnusedInclude, info);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t HandleGetHostFormsCount(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::string bundleName = data.ReadString();

    int32_t formCount = 0;
    int32_t result = svc.GetHostFormsCount(bundleName, formCount);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(formCount)) {
        HILOG_ERROR("write formCount failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleGetRunningFormInfos(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    bool isUnusedInclude = false;
    if (!data.ReadBool(isUnusedInclude)) {
        HILOG_ERROR("read isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<RunningFormInfo> runningFormInfos;
    ErrCode result = svc.GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(runningFormInfos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t HandleGetRunningFormInfosByBundleName(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isUnusedInclude = false;
    if (!data.ReadBool(isUnusedInclude)) {
        HILOG_ERROR("read isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<RunningFormInfo> runningFormInfos;
    ErrCode result = svc.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(runningFormInfos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t HandleRegisterPublishFormInterceptor(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.RegisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleUnregisterPublishFormInterceptor(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.UnregisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRegisterClickCallbackEventObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return svc.RegisterClickEventObserver(bundleName, formEventType, callerToken);
}

int32_t HandleUnregisterClickCallbackEventObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return svc.UnregisterClickEventObserver(bundleName, formEventType, callerToken);
}

int32_t HandleRegisterAddObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RegisterAddObserver(bundleName, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRegisterRemoveObserver(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RegisterRemoveObserver(bundleName, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRegisterFormRouterProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = svc.RegisterFormRouterProxy(formIds, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleUnregisterFormRouterProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    auto result = svc.UnregisterFormRouterProxy(formIds);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleUpdateProxyForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<FormProviderData> formProviderData(data.ReadParcelable<FormProviderData>());
    if (formProviderData == nullptr) {
        HILOG_ERROR("get formProviderData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormDataProxy> formDataProxies;
    if (!ReadFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("fail get formDataProxies");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.UpdateProxyForm(formId, *formProviderData, formDataProxies);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRequestPublishProxyForm(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("error to get want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    if (withFormBindingData) {
        formProviderData.reset(data.ReadParcelable<FormProviderData>());
        if (formProviderData == nullptr) {
            HILOG_ERROR("error to get formProviderData");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    std::vector<FormDataProxy> formDataProxies;
    if (!ReadFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("fail get formDataProxies");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t formId = 0;
    ErrCode result = svc.RequestPublishProxyForm(*want, withFormBindingData, formProviderData, formId, formDataProxies);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        reply.WriteInt64(formId);
    }
    return result;
}

int32_t HandleSetFormsRecyclable(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    int32_t result = svc.SetFormsRecyclable(formIds);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRecycleForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.RecycleForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleRecoverForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("read formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formIds.size() > Constants::MAX_FORM_IDS_SIZE) {
        HILOG_ERROR("formIds size %{public}zu exceeds limit %{public}d",
            formIds.size(), Constants::MAX_FORM_IDS_SIZE);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.RecoverForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleUpdateFormLocation(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t formLocation = 0;
    if (!data.ReadInt32(formLocation)) {
        HILOG_ERROR("read formLocation failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
        formLocation >= static_cast<int32_t>(Constants::FormLocation::FORM_LOCATION_END)) {
        HILOG_ERROR("formLocation not FormLocation enum, formLocation = %{public}d", formLocation);
        return ERR_APPEXECFWK_FORM_LOCATION_INVALID;
    }
    ErrCode result = svc.UpdateFormLocation(formId, formLocation);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

/**
 * @brief handle CreateForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t HandleRequestPublishFormWithSnapshot(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("error to get want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formBindingData = nullptr;
    if (withFormBindingData) {
        formBindingData.reset(data.ReadParcelable<FormProviderData>());
        if (formBindingData == nullptr) {
            HILOG_ERROR("error to get formBindingData");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    int64_t formId = 0;
    ErrCode result = svc.RequestPublishFormWithSnapshot(*want, withFormBindingData, formBindingData, formId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    } else {
        reply.WriteInt64(formId);
    }
    return result;
}

int32_t HandleBatchRefreshForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int32_t formRefreshType;
    if (!data.ReadInt32(formRefreshType)) {
        HILOG_ERROR("read formRefreshType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (formRefreshType < Constants::REFRESH_ALL_FORM || formRefreshType > Constants::REFRESH_SYSTEMAPP_FORM) {
        HILOG_ERROR("invalid formRefreshType:%{public}d", formRefreshType);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    ErrCode result = svc.BatchRefreshForms(formRefreshType);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleEnableForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (bundleName.empty()) {
        HILOG_ERROR("fail ReadString<bundleName>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = 0;
    if (!data.ReadInt32(userId)) {
        HILOG_ERROR("read userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool enable = false;
    if (!data.ReadBool(enable)) {
        HILOG_ERROR("read enable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.EnableForms(bundleName, userId, enable);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleIsFormBundleForbidden(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    bool result = svc.IsFormBundleForbidden(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleLockForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<FormLockInfo> formLockInfo;
    int32_t infoSize = 0;
    if (!data.ReadInt32(infoSize)) {
        HILOG_ERROR("read infoSize failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (infoSize < 0 || infoSize > static_cast<int32_t>(MAX_ALLOW_SIZE)) {
        HILOG_ERROR("infoSize exceeds limit: %{public}d", infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<FormLockInfo> info(data.ReadParcelable<FormLockInfo>());
        if (!info) {
            HILOG_ERROR("error to Read Parcelable infos");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        formLockInfo.push_back(*info);
    }

    int32_t dataValue = 0;
    if (!data.ReadInt32(dataValue)) {
        HILOG_ERROR("read dataValue failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    LockChangeType type = ParseLockChangeType(dataValue);
    if (type == LockChangeType::INVALID_PARAMETER) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = svc.LockForms(formLockInfo, type);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleIsFormProtected(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = svc.IsFormBundleProtected(bundleName, formId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleIsFormDebugSignature(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName;
    if (!data.ReadString(bundleName)) {
        HILOG_ERROR("read bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = svc.IsFormBundleDebugSignature(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleIsFormExempt(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = svc.IsFormBundleExempt(formId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleNotifyFormLocked(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isLocked = false;
    if (!data.ReadBool(isLocked)) {
        HILOG_ERROR("read isLocked failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.NotifyFormLocked(formId, isLocked);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUpdateFormSize(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    float width = 0.0f;
    if (!data.ReadFloat(width)) {
        HILOG_ERROR("read width failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    float height = 0.0f;
    if (!data.ReadFloat(height)) {
        HILOG_ERROR("read height failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    float borderWidth = 0.0f;
    if (!data.ReadFloat(borderWidth)) {
        HILOG_ERROR("read borderWidth failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    float formViewScale = 0.0f;
    if (!data.ReadFloat(formViewScale)) {
        HILOG_ERROR("read formViewScale failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleOpenFormEditAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string abilityName;
    if (!data.ReadString(abilityName)) {
        HILOG_ERROR("read abilityName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isMainPage = false;
    if (!data.ReadBool(isMainPage)) {
        HILOG_ERROR("read isMainPage failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.OpenFormEditAbility(abilityName, formId, isMainPage);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleCloseFormEditAbility(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    bool isMainPage = true;
    if (!data.ReadBool(isMainPage)) {
        HILOG_ERROR("fail to read isMainPage from parcel");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.CloseFormEditAbility(isMainPage);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterOverflowProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Handle save overflow proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterOverflowProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterOverflowProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterOverflowProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRequestOverflow(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<OverflowInfo> overflowInfoPtr(data.ReadParcelable<OverflowInfo>());
    if (overflowInfoPtr == nullptr) {
        HILOG_ERROR("Read oveflowInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isOverflow = false;
    if (!data.ReadBool(isOverflow)) {
        HILOG_ERROR("read isOverflow failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RequestOverflow(formId, *overflowInfoPtr, isOverflow);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterChangeSceneAnimationStateProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterChangeSceneAnimationStateProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterChangeSceneAnimationStateProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterChangeSceneAnimationStateProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleChangeSceneAnimationState(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t state = 0;
    if (!data.ReadInt32(state)) {
        HILOG_ERROR("read state failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (state < 0 || state > Constants::MAX_SCENE_ANIMATION_STATE) {
        HILOG_ERROR("invalid state %{public}d", state);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    ErrCode result = svc.ChangeSceneAnimationState(formId, state);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterGetFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("handle save query proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterGetFormRectProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterGetFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterGetFormRectProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleGetFormRect(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    Rect item;
    ErrCode result = svc.GetFormRect(formId, item);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write get form result result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!reply.WriteParcelable(&item)) {
            HILOG_ERROR("write form rect failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t HandleNotifyUpdateFormSize(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t newDimension = 0;
    if (!data.ReadInt32(newDimension)) {
        HILOG_ERROR("read newDimension failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Rect> newRect(data.ReadParcelable<Rect>());
    if (newRect == nullptr) {
        HILOG_ERROR("Read newRect failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.UpdateFormSize(formId, newDimension, *newRect);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterGetLiveFormStatusProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("handle save query proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterGetLiveFormStatusProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterGetLiveFormStatusProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterGetLiveFormStatusProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleIsFormDueControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormMajorInfo> formMajorInfo(data.ReadParcelable<FormMajorInfo>());
    if (formMajorInfo == nullptr) {
        HILOG_ERROR("Read formMajorInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isDisablePolicy = false;
    if (!data.ReadBool(isDisablePolicy)) {
        HILOG_ERROR("read isDisablePolicy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool result = svc.IsFormDueControl(*formMajorInfo, isDisablePolicy);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleReloadForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int32_t reloadNum = 0;
    std::string moduleName;
    if (!data.ReadString(moduleName)) {
        HILOG_ERROR("read moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string abilityName;
    if (!data.ReadString(abilityName)) {
        HILOG_ERROR("read abilityName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string formName;
    if (!data.ReadString(formName)) {
        HILOG_ERROR("read formName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.ReloadForms(reloadNum, moduleName, abilityName, formName);
    if (!reply.WriteInt32(reloadNum)) {
        HILOG_ERROR("Write reload number of forms failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleReloadAllForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int32_t reloadNum = 0;
    ErrCode result = svc.ReloadAllForms(reloadNum);
    if (!reply.WriteInt32(reloadNum)) {
        HILOG_ERROR("Write reload number of forms failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleSendNonTransparencyRatio(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t ratio = 0;
    if (!data.ReadInt32(ratio)) {
        HILOG_ERROR("read ratio failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.SendNonTransparencyRatio(formId, ratio);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterTemplateFormDetailInfoChange(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    ErrCode result = svc.RegisterTemplateFormDetailInfoChange(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterTemplateFormDetailInfoChange(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterTemplateFormDetailInfoChange();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUpdateTemplateFormDetailInfo(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<TemplateFormDetailInfo> templateFormInfo;
    int32_t size = 0;
    if (!data.ReadInt32(size)) {
        HILOG_ERROR("read size failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (size > Constants::TEMPLATE_FORM_MAX_SIZE) {
        HILOG_ERROR("size limit");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < size; i++) {
        std::unique_ptr<TemplateFormDetailInfo> templateFormDetailInfo(data.ReadParcelable<TemplateFormDetailInfo>());
        if (templateFormDetailInfo == nullptr) {
            HILOG_ERROR("read templateFormDetailInfo failed at index %{public}d.", i);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        templateFormInfo.push_back(*templateFormDetailInfo);
    }
    ErrCode result = svc.UpdateTemplateFormDetailInfo(templateFormInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write request result failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterPublishFormCrossBundleControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (!callerToken) {
        HILOG_ERROR("caller token is null");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterPublishFormCrossBundleControl(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterPublishFormCrossBundleControl(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterPublishFormCrossBundleControl();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleGetFormIdsByFormLocation(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<std::string> formIds;
    int32_t formLocation = 0;
    if (!data.ReadInt32(formLocation)) {
        HILOG_ERROR("read formLocation failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.GetFormIdsByFormLocation(formLocation, formIds);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        HILOG_INFO("result is ok");
        if (!reply.WriteStringVector(formIds)) {
            HILOG_ERROR("WriteStringVector<formIds> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    return ERR_OK;
}

int32_t HandleRegisterFormWantCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    auto callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("ReadRemoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterFormWantCallback(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterFormWantCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterFormWantCallback();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterUpdateFormsConfigCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterUpdateFormsConfigCallback(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write request result failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterUpdateFormsConfigCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    ErrCode result = svc.UnregisterUpdateFormsConfigCallback();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write request result failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUpdateFormsConfig(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int32_t size = 0;
    if (!data.ReadInt32(size)) {
        HILOG_ERROR("read size failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (size <= 0 || size > Constants::UPDATE_FORM_CONFIG_MAX_NUM) {
        HILOG_ERROR("invalid size: %{public}d, max: %{public}d", size, Constants::UPDATE_FORM_CONFIG_MAX_NUM);
        if (!reply.WriteInt32(ERR_APPEXECFWK_FORM_COMMON_CODE)) {
            HILOG_ERROR("write error code failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    std::vector<FormCustomConfig> configs;
    configs.reserve(size);
    for (int32_t i = 0; i < size; i++) {
        std::unique_ptr<FormCustomConfig> config(data.ReadParcelable<FormCustomConfig>());
        if (config == nullptr) {
            HILOG_ERROR("read config failed at index %{public}d.", i);
            if (!reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR)) {
                HILOG_ERROR("write error code failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            return ERR_OK;
        }
        configs.push_back(*config);
    }
    ErrCode result = svc.UpdateFormsConfig(configs);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed, result=%{public}d", result);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterDeleteFormsCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterDeleteFormsCallback(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write request result failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterDeleteFormsCallback(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    ErrCode result = svc.UnregisterDeleteFormsCallback();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write request result failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleDeleteForms(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int32_t size = 0;
    if (!data.ReadInt32(size)) {
        HILOG_ERROR("read size failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (size <= 0 || size > Constants::DELETE_FORMS_FILTER_MAX_NUM) {
        HILOG_ERROR("invalid size: %{public}d, max: %{public}d", size, Constants::DELETE_FORMS_FILTER_MAX_NUM);
        if (!reply.WriteInt32(ERR_APPEXECFWK_FORM_INVALID_PARAM)) {
            HILOG_ERROR("write error code failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    std::vector<FormRecordFilter> filters;
    filters.reserve(size);
    for (int32_t i = 0; i < size; i++) {
        std::unique_ptr<FormRecordFilter> filter(data.ReadParcelable<FormRecordFilter>());
        if (filter == nullptr) {
            HILOG_ERROR("read filter failed at index %{public}d.", i);
            if (!reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR)) {
                HILOG_ERROR("write error code failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            return ERR_OK;
        }
        filters.push_back(*filter);
    }
    ErrCode result = svc.DeleteForms(filters);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed, result=%{public}d", result);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterFormHostService(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormHostServiceInfo> service(data.ReadParcelable<FormHostServiceInfo>());
    if (service == nullptr) {
        HILOG_ERROR("read FormHostServiceInfo failed");
        if (!reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    int64_t serviceId = -1;
    ErrCode result = svc.RegisterFormHostService(*service, serviceId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK && !reply.WriteInt64(serviceId)) {
        HILOG_ERROR("write serviceId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterFormHostService(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t serviceId = 0;
    if (!data.ReadInt64(serviceId)) {
        HILOG_ERROR("read serviceId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.UnregisterFormHostService(serviceId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleGetAvailableFormHostServices(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<PeerFormHostServiceInfo> services;
    ErrCode result = svc.GetAvailableFormHostServices(services);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK) {
        if (!WriteParcelableVector(services, reply)) {
            HILOG_ERROR("write services failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t HandleRequestPublishFormCrossDevice(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormCrossDeviceRequest> request(data.ReadParcelable<FormCrossDeviceRequest>());
    if (request == nullptr) {
        HILOG_ERROR("read FormCrossDeviceRequest failed");
        if (!reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    sptr<IRemoteObject> callback = data.ReadRemoteObject();
    if (callerToken == nullptr || callback == nullptr) {
        HILOG_ERROR("ReadRemoteObject failed");
        if (!reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_OK;
    }
    ErrCode result = svc.RequestPublishFormCrossDevice(*request, callerToken, callback);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleRegisterGetVisibleFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("handle save query visible form rect proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("read callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = svc.RegisterGetVisibleFormRectProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleUnregisterGetVisibleFormRectProxy(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = svc.UnregisterGetVisibleFormRectProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleGetVisibleFormRect(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = 0;
    if (!data.ReadInt64(formId)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    Rect rect;
    ErrCode result = svc.GetVisibleFormRect(formId, rect);
    if (!reply.WriteInt32(result)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (result == ERR_OK && !reply.WriteParcelable(&rect)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t HandleOpenFormManagePage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.OpenFormManagePage(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleOpenFormEditPage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = svc.OpenFormEditPage(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t HandleOpenLiveFormPage(IFormMgr &svc, MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::string formId = data.ReadString();
    int32_t result = svc.OpenLiveFormPage(*want, formId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}
} // namespace FormIpcHandlers
} // namespace AppExecFwk
} // namespace OHOS
