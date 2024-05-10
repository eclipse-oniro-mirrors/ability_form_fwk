/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "form_mgr_stub.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_info.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include <vector>

namespace OHOS {
namespace AppExecFwk {
const int32_t LIMIT_PARCEL_SIZE = 1024;
constexpr size_t MAX_PARCEL_CAPACITY = 4 * 1024 * 1024; // 4M

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

FormMgrStub::FormMgrStub()
{
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM)] =
        &FormMgrStub::HandleAddForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_FORM)] =
        &FormMgrStub::HandleDeleteForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_FORM)] =
        &FormMgrStub::HandleReleaseForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM)] =
        &FormMgrStub::HandleUpdateForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_FORM)] =
        &FormMgrStub::HandleRequestForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE)] =
        &FormMgrStub::HandleNotifyWhetherVisibleForms;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM)] =
        &FormMgrStub::HandleCastTempForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS)] =
        &FormMgrStub::HandleDumpStorageFormInfos;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME)] =
        &FormMgrStub::HandleDumpFormInfoByBundleName;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID)] =
        &FormMgrStub::HandleDumpFormInfoByFormId;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID)] =
        &FormMgrStub::HandleDumpFormTimerByFormId;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME)] =
        &FormMgrStub::HandleSetNextRefreshTime;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE)] =
        &FormMgrStub::HandleLifecycleUpdate;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT)] =
        &FormMgrStub::HandleMessageEvent;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS)] =
        &FormMgrStub::HandleDeleteInvalidForms;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE)] =
        &FormMgrStub::HandleAcquireFormState;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE)] =
        &FormMgrStub::HandleNotifyFormsVisible;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED)] =
        &FormMgrStub::HandleNotifyFormsPrivacyProtected;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE)] =
        &FormMgrStub::HandleNotifyFormsEnableUpdate;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO)] =
        &FormMgrStub::HandleGetAllFormsInfo;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP)] =
        &FormMgrStub::HandleGetFormsInfoByApp;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE)] =
        &FormMgrStub::HandleGetFormsInfoByModule;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER)] =
        &FormMgrStub::HandleGetFormsInfoByFilter;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO)] =
        &FormMgrStub::HandleGetFormsInfo;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ROUTER_EVENT)] =
        &FormMgrStub::HandleRouterEvent;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT)] =
        &FormMgrStub::HandleBackgroundEvent;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM)] =
        &FormMgrStub::HandleRequestPublishForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SHARE_FORM)] =
        &FormMgrStub::HandleShareForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE)] =
        &FormMgrStub::HandleRecvFormShareInfoFromRemote;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED)] =
        &FormMgrStub::HandleIsRequestPublishFormSupported;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY)] =
        &FormMgrStub::HandleStartAbility;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHECK_FMS_READY)] =
        &FormMgrStub::HandleCheckFMSReady;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STOP_RENDERING_FORM)] =
        &FormMgrStub::HandleStopRenderingForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE)] =
        &FormMgrStub::HandleRegisterFormAddObserverByBundle;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE)] =
        &FormMgrStub::HandleRegisterFormRemoveObserverByBundle;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_DATA)] =
        &FormMgrStub::HandleAcquireFormData;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT)] =
        &FormMgrStub::HandleGetFormsCount;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT)] =
        &FormMgrStub::HandleGetHostFormsCount;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS)] =
        &FormMgrStub::HandleGetRunningFormInfos;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE)] =
        &FormMgrStub::HandleGetRunningFormInfosByBundleName;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER)] =
        &FormMgrStub::HandleGetFormInstancesByFilter;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID)] =
        &FormMgrStub::HandleGetFormInstanceById;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER)] =
        &FormMgrStub::HandleRegisterAddObserver;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER)] =
        &FormMgrStub::HandleRegisterRemoveObserver;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM)] =
        &FormMgrStub::HandleUpdateProxyForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM)] =
        &FormMgrStub::HandleRequestPublishProxyForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_RENDERER)] =
        &FormMgrStub::HandleReleaseRenderer;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR)] =
        &FormMgrStub::HandleRegisterPublishFormInterceptor;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR)] =
        &FormMgrStub::HandleUnregisterPublishFormInterceptor;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER)] =
        &FormMgrStub::HandleRegisterClickCallbackEventObserver;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER)] =
        &FormMgrStub::HandleUnregisterClickCallbackEventObserver;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY)] =
        &FormMgrStub::HandleRegisterFormRouterProxy;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY)] =
        &FormMgrStub::HandleUnregisterFormRouterProxy;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_FORMS_RECYCLABLE)] =
        &FormMgrStub::HandleSetFormsRecyclable;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECYCLE_FORMS)] =
        &FormMgrStub::HandleRecycleForms;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECOVER_FORMS)] =
        &FormMgrStub::HandleRecoverForms;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID)] =
        &FormMgrStub::HandleHasFormVisible;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM_LOCATION)] =
        &FormMgrStub::HandleUpdateFormLocation;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT)] =
        &FormMgrStub::HandleSetPublishFormResult;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_ADD_FORM_RESULT)] =
        &FormMgrStub::HandleAcquireAddFormResult;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CREATE_FORM)] =
        &FormMgrStub::HandleCreateForm;
    memberFuncMap_[static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT)] =
        &FormMgrStub::HandleRequestPublishFormWithSnapshot;
}

FormMgrStub::~FormMgrStub()
{
    memberFuncMap_.clear();
}

/**
 * @brief handle remote request.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("FormMgrStub::OnReceived, code = %{public}u, flags= %{public}d.", code, option.GetFlags());
    std::u16string descriptor = FormMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("%{public}s failed, remote is not equal to local descriptor", __func__);
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
/**
 * @brief handle AddForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleAddForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<FormReqInfo>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to RemoteObject invalidate", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    FormJsInfo formJsInfo;
    int32_t result = AddForm(formId, *want, client, formJsInfo);
    reply.WriteInt32(result);
    reply.WriteParcelable(&formJsInfo);

    return result;
}

/**
 * @brief handle CreateForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleCreateForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("failed to ReadParcelable");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    RunningFormInfo runningFormInfo;
    int32_t result = CreateForm(*want, runningFormInfo);
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
int32_t FormMgrStub::HandleDeleteForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = DeleteForm(formId, client);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle DeleteFormByCompId message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleStopRenderingForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string compId = data.ReadString();
    int32_t result = StopRenderingForm(formId, compId);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle ReleaseForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleReleaseForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool delCache = data.ReadBool();

    int32_t result = ReleaseForm(formId, client, delCache);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle UpdateForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleUpdateForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<FormProviderData> formBindingData(data.ReadParcelable<FormProviderData>());
    if (formBindingData == nullptr) {
        HILOG_ERROR("%{public}s, failed to get formBindingData.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = UpdateForm(formId, *formBindingData);
    reply.WriteInt32(result);
    return result;
}
/**
     * @brief handle SetNextRefreshTime message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
int32_t FormMgrStub::HandleSetNextRefreshTime(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    int64_t nextTime = data.ReadInt64();
    int32_t result = SetNextRefreshTime(formId, nextTime);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief handle ReleaseRenderer message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleReleaseRenderer(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string compId = data.ReadString();
    int32_t result = ReleaseRenderer(formId, compId);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief handle RequestPublishForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormMgrStub::HandleRequestPublishForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("%{public}s, failed to get want.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    if (withFormBindingData) {
        formProviderData.reset(data.ReadParcelable<FormProviderData>());
        if (formProviderData == nullptr) {
            HILOG_ERROR("%{public}s, failed to get formProviderData.", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    int64_t formId = 0;
    ErrCode result = RequestPublishForm(*want, withFormBindingData, formProviderData, formId);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        reply.WriteInt64(formId);
    }
    return result;
}

ErrCode FormMgrStub::HandleSetPublishFormResult(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.message = data.ReadString();
    int32_t err = data.ReadInt32();
    errorCodeInfo.code = (Constants::PublishFormErrorCode)(err) ;
    ErrCode result = SetPublishFormResult(formId, errorCodeInfo);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleAcquireAddFormResult(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    ErrCode result = AcquireAddFormResult(formId);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle LifecycleUpdate message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleLifecycleUpdate(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool updateType = data.ReadBool();
    int32_t result = LifecycleUpdate(formIds, client, updateType);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle RequestForm message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleRequestForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);

    int64_t formId = data.ReadInt64();

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = RequestForm(formId, client, *want);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief handle NotifyVisibleForms message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleNotifyWhetherVisibleForms(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int64_t> formIds;
    bool ret = data.ReadInt64Vector(&formIds);
    if (!ret) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t formVisibleType = data.ReadInt32();

    int32_t result = NotifyWhetherVisibleForms(formIds, client, formVisibleType);
    reply.WriteInt32(result);
    return result;
}


/**
 * @brief Handle HasFormVisible message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleHasFormVisible(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    uint32_t tokenId = data.ReadUint32();
    bool result = HasFormVisible(tokenId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("%{public}s, failed to write action", __func__);
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
int32_t FormMgrStub::HandleCastTempForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = CastTempForm(formId, client);
    reply.WriteInt32(result);
    return result;
}
/**
 * @brief Handle DumpStorageFormInfos message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleDumpStorageFormInfos(MessageParcel &data, MessageParcel &reply)
{
    std::string formInfos;
    int32_t result = DumpStorageFormInfos(formInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(formInfos, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("%{public}s, failed to WriteStringVector<dumpInfos>", __func__);
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
int32_t FormMgrStub::HandleDumpFormInfoByBundleName(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    std::string formInfos;
    int32_t result = DumpFormInfoByBundleName(bundleName, formInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        HILOG_DEBUG("%{public}s, formInfos: %{public}s", __func__, formInfos.c_str());
        std::vector<std::string> dumpInfos;
        SplitString(formInfos, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("%{public}s, failed to WriteStringVector<dumpInfos>", __func__);
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
int32_t FormMgrStub::HandleDumpFormInfoByFormId(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string formInfo;
    int32_t result = DumpFormInfoByFormId(formId, formInfo);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(formInfo, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("%{public}s, failed to WriteStringVector<dumpInfos>", __func__);
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
int32_t FormMgrStub::HandleDumpFormTimerByFormId(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::string isTimingService;
    int32_t result = DumpFormTimerByFormId(formId, isTimingService);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        std::vector<std::string> dumpInfos;
        SplitString(isTimingService, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            HILOG_ERROR("%{public}s, failed to WriteStringVector<dumpInfos>", __func__);
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
int32_t FormMgrStub::HandleMessageEvent(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = MessageEvent(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief Handle RouterEvent message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleRouterEvent(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = RouterEvent(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief Handle Background message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleBackgroundEvent(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable<Want>", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = BackgroundEvent(formId, *want, client);
    reply.WriteInt32(result);
    return result;
}

/**
 * @brief Handle DeleteInvalidForms message.
 * @param data input param.
 * @param reply output param.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormMgrStub::HandleDeleteInvalidForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("%{public}s, failed to ReadInt64Vector", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t numFormsDeleted = 0;
    int32_t result = DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(numFormsDeleted)) {
        HILOG_ERROR("%{public}s, failed to write numFormsDeleted", __func__);
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
int32_t FormMgrStub::HandleAcquireFormState(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    FormStateInfo stateInfo {};
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("%{public}s, failed to ReadParcelable want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = AcquireFormState(*want, callerToken, stateInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32((int32_t)stateInfo.state)) {
        HILOG_ERROR("%{public}s, failed to write state", __func__);
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
int32_t FormMgrStub::HandleNotifyFormsVisible(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("%{public}s, failed to ReadInt64Vector", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isVisible = false;
    if (!data.ReadBool(isVisible)) {
        HILOG_ERROR("%{public}s, failed to ReadBool", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormsVisible(formIds, isVisible, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleNotifyFormsPrivacyProtected(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("%{public}s, failed to ReadInt64Vector", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isProtected = false;
    if (!data.ReadBool(isProtected)) {
        HILOG_ERROR("%{public}s, failed to ReadBool", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
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
int32_t FormMgrStub::HandleNotifyFormsEnableUpdate(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("%{public}s, failed to ReadInt64Vector", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isEnableUpdate = false;
    if (!data.ReadBool(isEnableUpdate)) {
        HILOG_ERROR("%{public}s, failed to ReadBool", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
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
int32_t FormMgrStub::HandleGetAllFormsInfo(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called. max parcel capacity : %{public}zu", __func__, MAX_PARCEL_CAPACITY);
    std::vector<FormInfo> infos;
    int32_t result = GetAllFormsInfo(infos);
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
int32_t FormMgrStub::HandleGetFormsInfoByApp(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::string bundleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = GetFormsInfoByApp(bundleName, infos);
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
int32_t FormMgrStub::HandleGetFormsInfoByModule(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<FormInfo> infos;
    int32_t result = GetFormsInfoByModule(bundleName, moduleName, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t FormMgrStub::HandleGetFormsInfoByFilter(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    FormInfoFilter filter;
    filter.bundleName = data.ReadString();
    filter.moduleName = data.ReadString();
    data.ReadInt32Vector(&filter.supportDimensions);
    data.ReadInt32Vector(&filter.supportShapes);

    std::vector<FormInfo> infos;
    int32_t result = GetFormsInfoByFilter(filter, infos);
    reply.WriteInt32(result);
    if (result == ERR_OK && !WriteParcelableVector(infos, reply)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleGetFormsInfo(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    // read filter from data.
    std::unique_ptr<FormInfoFilter> filter(data.ReadParcelable<FormInfoFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("%{public}s, failed to get filter.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write result of calling FMS into reply.
    std::vector<FormInfo> infos;
    // call FormMgrService to get formInfos into infos.
    int32_t result = GetFormsInfo(*filter, infos);
    reply.WriteBool(result);
    if (result == ERR_OK) {
        // write fetched formInfos into reply.
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t FormMgrStub::HandleShareForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    int64_t formId = data.ReadInt64();
    std::string deviceId = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t requestCode = data.ReadInt64();

    auto result = ShareForm(formId, deviceId, callerToken, requestCode);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleAcquireFormData(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("called.");
    int64_t formId = data.ReadInt64();
    int64_t requestCode = data.ReadInt64();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write result of calling FMS into reply.
    AAFwk::WantParams customizeData;
    // call FormMgrService to get formData into data.
    int32_t result = AcquireFormData(formId, requestCode, callerToken, customizeData);
    reply.WriteInt32(result);
    reply.WriteParcelable(&customizeData);
    return result;
}

int32_t FormMgrStub::HandleRecvFormShareInfoFromRemote(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::unique_ptr<FormShareInfo> info(data.ReadParcelable<FormShareInfo>());
    if (!info) {
        HILOG_ERROR("failed to ReadParcelable<FormShareInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RecvFormShareInfoFromRemote(*info);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleIsRequestPublishFormSupported(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    bool result = IsRequestPublishFormSupported();
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("%{public}s, failed to write action", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleStartAbility(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    // retrieve want
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("%{public}s, failed to get want.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // retrieve callerToken
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s, failed to get remote object.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = StartAbility(*want, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("%{public}s, failed to write result", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleCheckFMSReady(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    bool result = CheckFMSReady();
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("%{public}s, failed to write action", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleRegisterFormAddObserverByBundle(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");

    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormAddObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleRegisterFormRemoveObserverByBundle(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");

    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleGetFormsCount(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    bool isTempFormFlag = false;
    if (!data.ReadBool(isTempFormFlag)) {
        HILOG_ERROR("%{public}s, failed to read temp flag", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t formCount = 0;
    int32_t result = GetFormsCount(isTempFormFlag, formCount);
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

int32_t FormMgrStub::HandleGetFormInstancesByFilter(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::unique_ptr<FormInstancesFilter> filter(data.ReadParcelable<FormInstancesFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("failed to get filter.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormInstance> infos;
    auto result = GetFormInstancesByFilter(*filter, infos);
    HILOG_DEBUG("info size = %{public}zu", infos.size());
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        HILOG_INFO("result i true.");
        if (!WriteParcelableVector(infos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleGetFormInstanceById(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    int64_t formId = data.ReadInt64();
    bool isUnusedInclude = data.ReadBool();
    FormInstance info;
    auto result = GetFormInstanceById(formId, isUnusedInclude, info);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleGetHostFormsCount(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::string bundleName = data.ReadString();

    int32_t formCount = 0;
    int32_t result = GetHostFormsCount(bundleName, formCount);
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

ErrCode FormMgrStub::HandleGetRunningFormInfos(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    bool isUnusedInclude = data.ReadBool();
    std::vector<RunningFormInfo> runningFormInfos;
    ErrCode result = GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(runningFormInfos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

ErrCode FormMgrStub::HandleGetRunningFormInfosByBundleName(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::string bundleName = data.ReadString();
    bool isUnusedInclude = data.ReadBool();
    std::vector<RunningFormInfo> runningFormInfos;
    ErrCode result = GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        if (!WriteParcelableVector(runningFormInfos, reply)) {
            HILOG_ERROR("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return result;
}

int32_t FormMgrStub::HandleRegisterPublishFormInterceptor(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RegisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleUnregisterPublishFormInterceptor(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = UnregisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRegisterClickCallbackEventObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("Failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return RegisterClickEventObserver(bundleName, formEventType, callerToken);
}

int32_t FormMgrStub::HandleUnregisterClickCallbackEventObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("Failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return UnregisterClickEventObserver(bundleName, formEventType, callerToken);
}

/**
 * @brief Write a parcelabe vector objects to the proxy node.
 * @param parcelableVector Indicates the objects to be write.
 * @param reply Indicates the reply to be sent;
 * @return Returns true if objects send successfully; returns false otherwise.
 */
template<typename T>
bool FormMgrStub::WriteParcelableVector(std::vector<T> &parcelableVector, Parcel &reply)
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

ErrCode FormMgrStub::HandleRegisterAddObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterAddObserver(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleRegisterRemoveObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterRemoveObserver(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleRegisterFormRouterProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("Failed to ReadInt64Vector.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("Failed to get remote object.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormRouterProxy(formIds, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleUnregisterFormRouterProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("Failed to ReadInt64Vector.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = UnregisterFormRouterProxy(formIds);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleUpdateProxyForm(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();
    std::unique_ptr<FormProviderData> formProviderData(data.ReadParcelable<FormProviderData>());
    if (formProviderData == nullptr) {
        HILOG_ERROR("%{public}s, failed to get formProviderData.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormDataProxy> formDataProxies;
    if (!ReadFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("failed to get formDataProxies.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = UpdateProxyForm(formId, *formProviderData, formDataProxies);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleRequestPublishProxyForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("%{public}s, error to get want.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    if (withFormBindingData) {
        formProviderData.reset(data.ReadParcelable<FormProviderData>());
        if (formProviderData == nullptr) {
            HILOG_ERROR("%{public}s, error to get formProviderData.", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    std::vector<FormDataProxy> formDataProxies;
    if (!ReadFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("failed to get formDataProxies.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t formId = 0;
    ErrCode result = RequestPublishProxyForm(*want, withFormBindingData, formProviderData, formId, formDataProxies);
    reply.WriteInt32(result);
    if (result == ERR_OK) {
        reply.WriteInt64(formId);
    }
    return result;
}
bool FormMgrStub::ReadFormDataProxies(MessageParcel &data, std::vector<FormDataProxy> &formDataProxies)
{
    auto number = data.ReadInt32();
    HILOG_DEBUG("proxies number: %{public}d.", number);
    if (number < 0 || number > INT16_MAX) {
        HILOG_ERROR("proxies number over limit: %{public}d.", number);
        return false;
    }

    for (int32_t i = 0; i < number; i++) {
        FormDataProxy formDataProxy("", "");
        formDataProxy.key = Str16ToStr8(data.ReadString16());
        formDataProxy.subscribeId = Str16ToStr8(data.ReadString16());
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

int32_t FormMgrStub::HandleSetFormsRecyclable(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("failed to ReadInt64Vector");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = SetFormsRecyclable(formIds);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRecycleForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("failed to ReadInt64Vector");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("failed to ReadParcelable<Want>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecycleForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRecoverForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("failed to ReadInt64Vector");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("failed to ReadParcelable<Want>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecoverForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleUpdateFormLocation(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    int64_t formId = data.ReadInt64();
    int32_t formLocation = data.ReadInt32();
    ErrCode result = UpdateFormLocation(formId, formLocation);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
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
ErrCode FormMgrStub::HandleRequestPublishFormWithSnapshot(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("%{public}s, error to get want.", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    bool withFormBindingData = data.ReadBool();
    std::unique_ptr<FormProviderData> formBindingData = nullptr;
    if (withFormBindingData) {
        formBindingData.reset(data.ReadParcelable<FormProviderData>());
        if (formBindingData == nullptr) {
            HILOG_ERROR("%{public}s, error to get formBindingData.", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    int64_t formId = 0;
    ErrCode result = RequestPublishFormWithSnapshot(*want, withFormBindingData, formBindingData, formId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("failed to write result");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    } else {
        reply.WriteInt64(formId);
    }

    return result;
}

}  // namespace AppExecFwk
}  // namespace OHOS