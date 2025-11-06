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
#include "running_form_info.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include <vector>

namespace OHOS {
namespace AppExecFwk {
const int32_t LIMIT_PARCEL_SIZE = 1024;
constexpr size_t MAX_PARCEL_CAPACITY = 4 * 1024 * 1024; // 4M
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

FormMgrStub::FormMgrStub()
{}

FormMgrStub::~FormMgrStub()
{}

/**
 * @brief handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("code= %{public}u,flags= %{public}d", code, option.GetFlags());
    std::u16string descriptor = FormMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("remote not equal to localDescriptor");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return OnRemoteRequestFirst(code, data, reply, option);
}

/**
 * @brief the first part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestFirst(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM):
            return HandleAddForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_FORM):
            return HandleDeleteForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_FORM):
            return HandleReleaseForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM):
            return HandleUpdateForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_FORM):
            return HandleRequestForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE):
            return HandleNotifyWhetherVisibleForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM):
            return HandleCastTempForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS):
            return HandleDumpStorageFormInfos(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME):
            return HandleDumpFormInfoByBundleName(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID):
            return HandleDumpFormInfoByFormId(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID):
            return HandleDumpFormTimerByFormId(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME):
            return HandleSetNextRefreshTime(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE):
            return HandleLifecycleUpdate(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT):
            return HandleMessageEvent(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS):
            return HandleDeleteInvalidForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE):
            return HandleAcquireFormState(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE):
            return HandleNotifyFormsVisible(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED):
            return HandleNotifyFormsPrivacyProtected(data, reply);
        default:
            return OnRemoteRequestSecond(code, data, reply, option);
    }
}

/**
 * @brief the second part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestSecond(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE):
            return HandleNotifyFormsEnableUpdate(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO):
            return HandleGetAllFormsInfo(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP):
            return HandleGetFormsInfoByApp(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE):
            return HandleGetFormsInfoByModule(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER):
            return HandleGetFormsInfoByFilter(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO):
            return HandleGetFormsInfo(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ROUTER_EVENT):
            return HandleRouterEvent(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT):
            return HandleBackgroundEvent(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM):
            return HandleRequestPublishForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SHARE_FORM):
            return HandleShareForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE):
            return HandleRecvFormShareInfoFromRemote(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED):
            return HandleIsRequestPublishFormSupported(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY):
            return HandleStartAbility(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHECK_FMS_READY):
            return HandleCheckFMSReady(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STOP_RENDERING_FORM):
            return HandleStopRenderingForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE):
            return HandleRegisterFormAddObserverByBundle(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE):
            return HandleRegisterFormRemoveObserverByBundle(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY_BY_FMS):
            return HandleStartAbilityByFms(data, reply);
        default:
            return OnRemoteRequestThird(code, data, reply, option);
    }
}

/**
 * @brief the third part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestThird(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_DATA):
            return HandleAcquireFormData(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT):
            return HandleGetFormsCount(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT):
            return HandleGetHostFormsCount(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS):
            return HandleGetRunningFormInfos(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE):
            return HandleGetRunningFormInfosByBundleName(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER):
            return HandleGetFormInstancesByFilter(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID):
            return HandleGetFormInstanceById(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER):
            return HandleRegisterAddObserver(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER):
            return HandleRegisterRemoveObserver(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM):
            return HandleUpdateProxyForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM):
            return HandleRequestPublishProxyForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_RENDERER):
            return HandleReleaseRenderer(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR):
            return HandleRegisterPublishFormInterceptor(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR):
            return HandleUnregisterPublishFormInterceptor(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER):
            return HandleRegisterClickCallbackEventObserver(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_PEOTECTED):
            return HandleIsFormProtected(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_DEBUG_SIGNATURE):
            return HandleIsFormDebugSignature(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_LOCKED):
            return HandleNotifyFormLocked(data, reply);
        default:
            return OnRemoteRequestFourth(code, data, reply, option);
    }
}

/**
 * @brief the fourth part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestFourth(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER):
            return HandleUnregisterClickCallbackEventObserver(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY):
            return HandleRegisterFormRouterProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY):
            return HandleUnregisterFormRouterProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_FORMS_RECYCLABLE):
            return HandleSetFormsRecyclable(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECYCLE_FORMS):
            return HandleRecycleForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECOVER_FORMS):
            return HandleRecoverForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID):
            return HandleHasFormVisible(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM_LOCATION):
            return HandleUpdateFormLocation(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT):
            return HandleSetPublishFormResult(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_ADD_FORM_RESULT):
            return HandleAcquireAddFormResult(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CREATE_FORM):
            return HandleCreateForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT):
            return HandleRequestPublishFormWithSnapshot(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_BATCH_REFRESH_FORMS):
            return HandleBatchRefreshForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ENABLE_FORMS):
            return HandleEnableForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_SYSTEM_APP_FORM):
            return HandleIsSystemAppForm(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_FORBIDDEN):
            return HandleIsFormBundleForbidden(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM_SIZE):
            return HandleUpdateFormSize(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LOCK_FORMS):
            return HandleLockForms(data, reply);
        default:
            return OnRemoteRequestFifth(code, data, reply, option);
    }
}

/**
 * @brief the fifth part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestFifth(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID):
            return HandleGetPublishedFormInfoById(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFOS):
            return HandleGetPublishedFormInfos(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_EXEMPT):
            return HandleIsFormExempt(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_OPEN_FORM_EDIT_ABILITY):
            return HandleOpenFormEditAbility(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_OVERFLOW_PROXY):
            return HandleRegisterOverflowProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_OVERFLOW_PROXY):
            return HandleUnregisterOverflowProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_OVERFLOW):
            return HandleRequestOverflow(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY):
            return HandleRegisterChangeSceneAnimationStateProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY):
            return HandleUnregisterChangeSceneAnimationStateProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHANGE_SCENE_ANIMATION_STATE):
            return HandleChangeSceneAnimationState(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY_BY_CROSS_BUNDLE):
            return HandleStartAbilityByCrossBundle(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_GET_FORM_RECT):
            return HandleRegisterGetFormRectProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_GET_FORM_RECT):
            return HandleUnregisterGetFormRectProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_RECT):
            return HandleGetFormRect(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_UPDATE_FORM_SIZE):
            return HandleNotifyUpdateFormSize(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_GET_LIVE_FORM_STATUS):
            return HandleRegisterGetLiveFormStatusProxy(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_GET_LIVE_FORM_STATUS):
            return HandleUnregisterGetLiveFormStatusProxy(data, reply);
        default:
            return OnRemoteRequestSixth(code, data, reply, option);
    }
}

/**
 * @brief the sixth part of handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequestSixth(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    switch (code) {
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELOAD_FORMS):
            return HandleReloadForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELOAD_ALL_FORMS):
            return HandleReloadAllForms(data, reply);
        case static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_DUE_CONTROL):
            return HandleIsFormDueControl(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
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
        HILOG_ERROR("fail ReadParcelable<FormReqInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    sptr<IRemoteObject> client = data.ReadRemoteObject();
    if (client == nullptr) {
        HILOG_ERROR("RemoteObject invalidate");
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
        HILOG_ERROR("fail ReadParcelable");
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
        HILOG_ERROR("fail get formBindingData");
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
        HILOG_ERROR("get remote object failed");
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
    HILOG_INFO("call");

    int64_t formId = data.ReadInt64();

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
    HILOG_DEBUG("call");
    uint32_t tokenId = data.ReadUint32();
    bool result = HasFormVisible(tokenId);
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
int32_t FormMgrStub::HandleDumpFormInfoByBundleName(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    std::string formInfos;
    int32_t result = DumpFormInfoByBundleName(bundleName, formInfos);
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
int32_t FormMgrStub::HandleMessageEvent(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
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
    HILOG_INFO("call");
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
    HILOG_INFO("call");
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
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t numFormsDeleted = 0;
    int32_t result = DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
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
int32_t FormMgrStub::HandleAcquireFormState(MessageParcel &data, MessageParcel &reply)
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
    int32_t result = AcquireFormState(*want, callerToken, stateInfo);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32((int32_t)stateInfo.state)) {
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
int32_t FormMgrStub::HandleNotifyFormsVisible(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
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

    int32_t result = NotifyFormsVisible(formIds, isVisible, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleNotifyFormsPrivacyProtected(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
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

    int32_t result = NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
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
int32_t FormMgrStub::HandleNotifyFormsEnableUpdate(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
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

    int32_t result = NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
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
int32_t FormMgrStub::HandleGetAllFormsInfo(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("max parcel capacity:%{public}zu", MAX_PARCEL_CAPACITY);
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
    HILOG_DEBUG("call");
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
    HILOG_DEBUG("call");
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
    HILOG_DEBUG("call");
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
    HILOG_INFO("call");
    // read filter from data.
    std::unique_ptr<FormInfoFilter> filter(data.ReadParcelable<FormInfoFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("fail get filter");
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

int32_t FormMgrStub::HandleGetPublishedFormInfoById(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = data.ReadInt64();
    // write result of calling FMS into reply.
    RunningFormInfo info;
    // call FormMgrService to get formInfo.
    int32_t result = GetPublishedFormInfoById(formId, info);
    reply.WriteBool(result);
    if (result == ERR_OK && !reply.WriteParcelable(&info)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleGetPublishedFormInfos(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    // write result of calling FMS into reply.
    std::vector<RunningFormInfo> infos;
    // call FormMgrService to get formInfos into infos.
    int32_t result = GetPublishedFormInfos(infos);
    reply.WriteBool(result);
    if (result == ERR_OK && !WriteParcelableVector(infos, reply)) {
        HILOG_ERROR("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleShareForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = data.ReadInt64();
    std::string deviceId = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int64_t requestCode = data.ReadInt64();

    auto result = ShareForm(formId, deviceId, callerToken, requestCode);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleAcquireFormData(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    int64_t formId = data.ReadInt64();
    int64_t requestCode = data.ReadInt64();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
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
    HILOG_DEBUG("call");
    std::unique_ptr<FormShareInfo> info(data.ReadParcelable<FormShareInfo>());
    if (!info) {
        HILOG_ERROR("fail ReadParcelable<FormShareInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RecvFormShareInfoFromRemote(*info);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleIsRequestPublishFormSupported(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    bool result = IsRequestPublishFormSupported();
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleStartAbility(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    // retrieve want
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // retrieve callerToken
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remote object failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = StartAbility(*want, callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleStartAbilityByFms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    // retrieve want
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = StartAbilityByFms(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleStartAbilityByCrossBundle(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    // retrieve want
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("get want failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    int32_t result = StartAbilityByCrossBundle(*want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    return result;
}

int32_t FormMgrStub::HandleCheckFMSReady(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int32_t result = CheckFMSReady();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleIsSystemAppForm(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    bool result = IsSystemAppForm(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleRegisterFormAddObserverByBundle(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");

    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormAddObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleRegisterFormRemoveObserverByBundle(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");

    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

int32_t FormMgrStub::HandleGetFormsCount(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    bool isTempFormFlag = false;
    if (!data.ReadBool(isTempFormFlag)) {
        HILOG_ERROR("fail read temp flag");
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
    HILOG_DEBUG("call");
    std::unique_ptr<FormInstancesFilter> filter(data.ReadParcelable<FormInstancesFilter>());
    if (filter == nullptr) {
        HILOG_ERROR("fail get filter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormInstance> infos;
    auto result = GetFormInstancesByFilter(*filter, infos);
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

int32_t FormMgrStub::HandleGetFormInstanceById(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
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
    HILOG_INFO("call");
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
    HILOG_DEBUG("call");
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
    HILOG_DEBUG("call");
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
    HILOG_DEBUG("call");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RegisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleUnregisterPublishFormInterceptor(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    sptr<IRemoteObject> interceptor = data.ReadRemoteObject();
    if (interceptor == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = UnregisterPublishFormInterceptor(interceptor);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRegisterClickCallbackEventObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return RegisterClickEventObserver(bundleName, formEventType, callerToken);
}

int32_t FormMgrStub::HandleUnregisterClickCallbackEventObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    std::string formEventType = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
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
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterAddObserver(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleRegisterRemoveObserver(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterRemoveObserver(bundleName, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleRegisterFormRouterProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    if (callerToken == nullptr) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto result = RegisterFormRouterProxy(formIds, callerToken);
    reply.WriteInt32(result);
    return result;
}

ErrCode FormMgrStub::HandleUnregisterFormRouterProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
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
        HILOG_ERROR("get formProviderData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::vector<FormDataProxy> formDataProxies;
    if (!ReadFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("fail get formDataProxies");
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
    HILOG_DEBUG("proxies number:%{public}d", number);
    if (number < 0 || number > INT16_MAX) {
        HILOG_ERROR("proxies number over limit:%{public}d", number);
        return false;
    }

    for (int32_t i = 0; i < number; i++) {
        std::string key = Str16ToStr8(data.ReadString16());
        std::string subscribeId = Str16ToStr8(data.ReadString16());
        if (key.empty() || subscribeId.empty()) {
            continue;
        }
        FormDataProxy formDataProxy(key, subscribeId);
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

int32_t FormMgrStub::HandleSetFormsRecyclable(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = SetFormsRecyclable(formIds);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRecycleForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecycleForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleRecoverForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> formIds;
    if (!data.ReadInt64Vector(&formIds)) {
        HILOG_ERROR("ReadInt64Vector failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = RecoverForms(formIds, *want);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleUpdateFormLocation(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = data.ReadInt64();
    int32_t formLocation = data.ReadInt32();
    ErrCode result = UpdateFormLocation(formId, formLocation);
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
ErrCode FormMgrStub::HandleRequestPublishFormWithSnapshot(MessageParcel &data, MessageParcel &reply)
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
    ErrCode result = RequestPublishFormWithSnapshot(*want, withFormBindingData, formBindingData, formId);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    } else {
        reply.WriteInt64(formId);
    }
    return result;
}

ErrCode FormMgrStub::HandleBatchRefreshForms(MessageParcel &data, MessageParcel &reply)
{
    int32_t formRefreshType = data.ReadInt32();
    ErrCode result = BatchRefreshForms(formRefreshType);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

int32_t FormMgrStub::HandleEnableForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    if (bundleName.empty()) {
        HILOG_ERROR("fail ReadString<bundleName>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    bool enable = data.ReadBool();
    int32_t result = EnableForms(bundleName, userId, enable);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleIsFormBundleForbidden(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    bool result = IsFormBundleForbidden(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
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

int32_t FormMgrStub::HandleLockForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::vector<FormLockInfo> formLockInfo;
    int32_t infoSize = data.ReadInt32();
    if (infoSize > static_cast<int32_t>(MAX_ALLOW_SIZE)) {
        HILOG_ERROR("The vector/array size exceeds the security limit!");
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

    int32_t dataValue = data.ReadInt32();
    LockChangeType type = ParseLockChangeType(dataValue);
    if (type == LockChangeType::INVALID_PARAMETER) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t result = LockForms(formLockInfo, type);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleIsFormProtected(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    int64_t formId = data.ReadInt64();
    bool result = IsFormBundleProtected(bundleName, formId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleIsFormDebugSignature(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string bundleName = data.ReadString();
    bool result = IsFormBundleDebugSignature(bundleName);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleIsFormExempt(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = data.ReadInt64();
    bool result = IsFormBundleExempt(formId);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

int32_t FormMgrStub::HandleNotifyFormLocked(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = data.ReadInt64();
    bool isLocked = data.ReadBool();

    bool result = NotifyFormLocked(formId, isLocked);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write action failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleUpdateFormSize(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    int64_t formId = data.ReadInt64();
    float width = data.ReadFloat();
    float height = data.ReadFloat();
    float borderWidth = data.ReadFloat();
    ErrCode result = UpdateFormSize(formId, width, height, borderWidth);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleOpenFormEditAbility(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::string abilityName = data.ReadString();
    int64_t formId = data.ReadInt64();
    bool isMainPage = data.ReadBool();
    ErrCode result = OpenFormEditAbility(abilityName, formId, isMainPage);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return result;
}

ErrCode FormMgrStub::HandleRegisterOverflowProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Handle save overflow proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    ErrCode result = RegisterOverflowProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleUnregisterOverflowProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = UnregisterOverflowProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleRequestOverflow(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = data.ReadInt64();
    OverflowInfo* overflowInfoPtr = data.ReadParcelable<OverflowInfo>();
    if (overflowInfoPtr == nullptr) {
        HILOG_ERROR("Read oveflowInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isOverflow = data.ReadBool();
    ErrCode result = RequestOverflow(formId, *overflowInfoPtr, isOverflow);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        delete overflowInfoPtr;
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    delete overflowInfoPtr;
    return ERR_OK;
}

ErrCode FormMgrStub::HandleRegisterChangeSceneAnimationStateProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    ErrCode result = RegisterChangeSceneAnimationStateProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleUnregisterChangeSceneAnimationStateProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = UnregisterChangeSceneAnimationStateProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleChangeSceneAnimationState(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = data.ReadInt64();
    int32_t state = data.ReadInt32();
    ErrCode result = ChangeSceneAnimationState(formId, state);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleRegisterGetFormRectProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("handle save query proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    ErrCode result = RegisterGetFormRectProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleUnregisterGetFormRectProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = UnregisterGetFormRectProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
 
ErrCode FormMgrStub::HandleGetFormRect(MessageParcel &data, MessageParcel &reply)
{
    int64_t formId = data.ReadInt64();

    Rect item;
    ErrCode result = GetFormRect(formId, item);
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

ErrCode FormMgrStub::HandleNotifyUpdateFormSize(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int64_t formId = data.ReadInt64();
    int32_t newDimension = data.ReadInt32();
    std::unique_ptr<Rect> newRect(data.ReadParcelable<Rect>());
    if (newRect == nullptr) {
        HILOG_ERROR("Read newRect failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode result = UpdateFormSize(formId, newDimension, *newRect);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("Write request result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleRegisterGetLiveFormStatusProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("handle save query proxy to service");
    sptr<IRemoteObject> callerToken = data.ReadRemoteObject();
    ErrCode result = RegisterGetLiveFormStatusProxy(callerToken);
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write proxy failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
 
ErrCode FormMgrStub::HandleUnregisterGetLiveFormStatusProxy(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("call");
    ErrCode result = UnregisterGetLiveFormStatusProxy();
    if (!reply.WriteInt32(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode FormMgrStub::HandleReloadForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int32_t reloadNum = 0;
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    std::string formName = data.ReadString();
    ErrCode result = ReloadForms(reloadNum, moduleName, abilityName, formName);
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

ErrCode FormMgrStub::HandleReloadAllForms(MessageParcel &data, MessageParcel &reply)
{
    HILOG_INFO("Call");
    int32_t reloadNum = 0;
    ErrCode result = ReloadAllForms(reloadNum);
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

ErrCode FormMgrStub::HandleIsFormDueControl(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("call");
    std::unique_ptr<FormMajorInfo> formMajorInfo(data.ReadParcelable<FormMajorInfo>());
    if (formMajorInfo == nullptr) {
        HILOG_ERROR("Read formMajorInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isDisablePolicy = data.ReadBool();
    bool result = IsFormDueControl(*formMajorInfo, isDisablePolicy);
    if (!reply.WriteBool(result)) {
        HILOG_ERROR("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS