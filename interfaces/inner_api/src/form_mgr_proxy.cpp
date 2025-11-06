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

#include "form_mgr_proxy.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "running_form_info.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
}
FormMgrProxy::FormMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IFormMgr>(impl)
{}
/**
 * @brief Add form with want, send want to form manager service.
 * @param formId The Id of the forms to add.
 * @param want The want of the form to add.
 * @param callerToken Caller ability token.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::AddForm(
    const int64_t formId,
    const Want &want,
    const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write to interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write to formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write to want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write to callerTokenfailed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetParcelableInfo<FormJsInfo>(IFormMgr::Message::FORM_MGR_ADD_FORM, data, formInfo);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
    }

    return error;
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param want The want of the form to add.
 * @param runningFormInfo Running form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write to interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write to want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int ret = GetParcelableInfo<RunningFormInfo>(IFormMgr::Message::FORM_MGR_CREATE_FORM, data, runningFormInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail SendRequest:%{public}d", ret);
    }
    return ret;
}

/**
 * @brief Delete forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to delete.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_DELETE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int FormMgrProxy::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(compId)) {
        HILOG_ERROR("write compId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_STOP_RENDERING_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Release forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to release.
 * @param callerToken Caller ability token.
 * @param delCache Delete Cache or not.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(delCache)) {
        HILOG_ERROR("write delCache failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_RELEASE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Update form with formId, send formId to form manager service.
 * @param formId The Id of the form to update.
 * @param bundleName Provider ability bundleName.
 * @param FormProviderData Form binding data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::UpdateForm(const int64_t formId, const FormProviderData &FormProviderData)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&FormProviderData)) {
        HILOG_ERROR("write formBindingData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UPDATE_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        if (error == ERR_APPEXECFWK_PARCEL_ERROR) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Set next refresh time.
 * @param formId The Id of the form to update.
 * @param bundleName Provider ability bundleName.
 * @param nextTime Next refresh time.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(nextTime)) {
        HILOG_ERROR("write nextTime failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int FormMgrProxy::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(compId)) {
        HILOG_ERROR("write compId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_RELEASE_RENDERER,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RequestPublishForm(Want &want, bool withFormBindingData,
                                         std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("write withFormBindingData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("write formBindingData failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    MessageOption option;
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode == ERR_OK) {
        formId = reply.ReadInt64();
    }
    return errCode;
}

ErrCode FormMgrProxy::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(errorCodeInfo.message)) {
        HILOG_ERROR("fail write ErrorCode message");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(errorCodeInfo.code))) {
        HILOG_ERROR("write ErrorCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageOption option;
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::AcquireAddFormResult(const int64_t formId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_ACQUIRE_ADD_FORM_RESULT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int FormMgrProxy::LifecycleUpdate(
    const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken,
    bool updateType)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(updateType)) {
        HILOG_ERROR("write nextTime failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    return reply.ReadInt32();
}
/**
 * @brief Request form with formId and want, send formId and want to form manager service.
 * @param formId The Id of the form to update.
 * @param callerToken Caller ability token.
 * @param want The want of the form to add.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HILOG_INFO("call");

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REQUEST_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Form visible/invisible notify, send formIds to form manager service.
 * @param formIds The Id list of the forms to notify.
 * @param callerToken Caller ability token.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::NotifyWhetherVisibleForms(
    const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken,
    const int32_t formVisibleType)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(formVisibleType)) {
        HILOG_ERROR("fail write formVisibleType");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Query whether has visible form by tokenId.
 * @param tokenId Unique identification of application.
 * @return Returns true if has visible form, false otherwise.
 */
bool FormMgrProxy::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("call");

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        HILOG_ERROR("fail write tokenId");
        return false;
    }

    // send request
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }

    // retrieve and return result.
    return reply.ReadBool();
}

/**
 * @brief temp form to normal form.
 * @param formId The Id of the form.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("callerToken is write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}
/**
 * @brief Dump all of form storage infos.
 * @param formInfos All of form storage infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DumpStorageFormInfos(std::string &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("GetStringInfo:%{public}d failed", error);
    }

    return error;
}
/**
 * @brief Dump form info by a bundle name.
 * @param bundleName The bundle name of form provider.
 * @param formInfos Form infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("GetStringInfo:%{public}d failed", error);
    }

    return error;
}
/**
 * @brief Dump form info by a bundle name.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID, data, formInfo);
    if (error != ERR_OK) {
        HILOG_ERROR("GetStringInfo:%{public}d failed", error);
    }

    return error;
}
/**
 * @brief Dump timer info by form id.
 * @param formId The id of the form.
 * @param formInfo Form timer info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID, data, isTimingService);
    if (error != ERR_OK) {
        HILOG_ERROR("GetStringInfo:%{public}d failed", error);
    }

    return error;
}
/**
 * @brief Process js message event.
 * @param formId Indicates the unique id of form.
 * @param want information passed to supplier.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrProxy::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("error to write want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("error to write callerToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Process Background event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrProxy::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

/**
 * @brief Process js router event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgrProxy::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write to interface token error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write to formId error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write to want error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write to callerToken error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_ROUTER_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

template<typename T>
int  FormMgrProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        HILOG_ERROR("invalid size = %{public}d", infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("error to Read Parcelable infos");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }
    HILOG_DEBUG("get parcelable infos success");
    return ERR_OK;
}
bool FormMgrProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(IFormMgr::GetDescriptor())) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    return true;
}
int FormMgrProxy::GetStringInfo(IFormMgr::Message code, MessageParcel &data, std::string &stringInfo)
{
    HILOG_DEBUG("GetStringInfo start");
    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("error to read reply result");
        return error;
    }
    std::vector<std::string> stringInfoList;
    if (!reply.ReadStringVector(&stringInfoList)) {
        HILOG_ERROR("fail read string vector from reply");
        return false;
    }
    if (stringInfoList.empty()) {
        HILOG_INFO("No string info");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    for (const auto &info : stringInfoList) {
        stringInfo += info;
    }
    HILOG_DEBUG("get string info success");
    return ERR_OK;
}
int FormMgrProxy::GetFormsInfo(IFormMgr::Message code, MessageParcel &data, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("GetFormsInfo start");
    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read reply result fail");
        return error;
    }

    return GetParcelableInfos<FormInfo>(reply, formInfos);
}

int FormMgrProxy::GetPublishedFormInfoById(IFormMgr::Message code, MessageParcel &data, RunningFormInfo &formInfo)
{
    HILOG_DEBUG("GetPublishedFormInfoById start");

    auto error = GetParcelableInfo<RunningFormInfo>(code, data, formInfo);
    if (error != ERR_OK) {
        HILOG_ERROR("get parcelable info failed");
    }

    return error;
}

int FormMgrProxy::GetPublishedFormInfos(IFormMgr::Message code, MessageParcel &data,
                                        std::vector<RunningFormInfo> &formInfos)
{
    HILOG_DEBUG("GetPublishedFormInfos start");
    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read reply result fail");
        return error;
    }

    return GetParcelableInfos<RunningFormInfo>(reply, formInfos);
}

ErrCode FormMgrProxy::GetRunningFormInfos(IFormMgr::Message code, MessageParcel &data,
    std::vector<RunningFormInfo> &runningFormInfos)
{
    ErrCode error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read replyResult failed");
        return error;
    }
    return GetParcelableInfos<RunningFormInfo>(reply, runningFormInfos);
}

template<typename T>
int FormMgrProxy::GetParcelableInfo(IFormMgr::Message code, MessageParcel &data, T &parcelableInfo)
{
    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return error;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (!info) {
        HILOG_ERROR("readParcelableInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelableInfo = *info;
    HILOG_DEBUG("get parcelable info success");
    return ERR_OK;
}

int FormMgrProxy::SendTransactCmd(IFormMgr::Message code, MessageParcel &data,
                                  MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("error to get remote object, cmd:%{public}d", code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("error to SendRequest:%{public}d,cmd:%{public}d", result, code);
        if (result == ERR_APPEXECFWK_PARCEL_ERROR) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return ERR_OK;
}

/**
 * @brief Delete the invalid forms.
 * @param formIds Indicates the ID of the valid forms.
 * @param callerToken Caller ability token.
 * @param numFormsDeleted Returns the number of the deleted forms.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                     int32_t &numFormsDeleted)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("error to write callerToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    numFormsDeleted = reply.ReadInt32();
    return result;
}

/**
 * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
 * @param want Indicates a set of parameters to be transparently passed to the form provider.
 * @param callerToken Caller ability token.
 * @param stateInfo Returns the form's state info of the specify.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
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
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    stateInfo.state = (FormState)reply.ReadInt32();
    stateInfo.want = want;
    return result;
}

/**
 * @brief Notify the form is visible or not.
 * @param formIds Indicates the ID of the forms.
 * @param isVisible Visible or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                     const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("error to write vector formIds");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isVisible)) {
        HILOG_ERROR("fail write bool isVisible");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write to callerToken failed ");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    return result;
}

int FormMgrProxy::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                              const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isProtected)) {
        HILOG_ERROR("fail write bool isProtected");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    return result;
}

/**
 * @brief Notify the form is enable to be updated or not.
 * @param formIds Indicates the ID of the forms.
 * @param isEnableUpdate enable update or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                          const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnableUpdate)) {
        HILOG_ERROR("write bool isEnableUpdate failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write error to callerToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    return result;
}

/**
 * @brief Get All FormsInfo.
 * @param formInfos Return the forms' information of all forms provided.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetAllFormsInfo:%{public}d", error);
    }

    return error;
}

/**
 * @brief Get forms info by bundle name .
 * @param bundleName Application name.
 * @param formInfos Return the forms' information of the specify application name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByApp:%{public}d", error);
    }

    return error;
}

/**
 * @brief Get forms info by bundle name and module name.
 * @param bundleName bundle name.
 * @param moduleName Module name of hap.
 * @param formInfos Return the forms' information of the specify bundle name and module name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrProxy::GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                                       std::vector<FormInfo> &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(moduleName)) {
        HILOG_ERROR("fail write moduleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByModule:%{public}d", error);
    }

    return error;
}

int FormMgrProxy::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(filter.bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(filter.moduleName)) {
        HILOG_ERROR("write moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32Vector(filter.supportDimensions)) {
        HILOG_ERROR("fail write vector supportDimensions");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32Vector(filter.supportShapes)) {
        HILOG_ERROR("fail write vector supportShapes");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByFilter:%{public}d", error);
    }

    return error;
}

ErrCode FormMgrProxy::GetRunningFormInfos(bool isUnusedInclude, std::vector<RunningFormInfo> &runningFormInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("write isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode error = GetRunningFormInfos(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS, data, runningFormInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetRunningFormInfos:%{public}d", error);
    }
    return error;
}

ErrCode FormMgrProxy::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedInclude, std::vector<RunningFormInfo> &runningFormInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("write isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode error = GetRunningFormInfos(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE,
        data, runningFormInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetRunningFormInfosByBundleName:%{public}d", error);
    }
    return error;
}

int32_t FormMgrProxy::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&filter)) {
        HILOG_ERROR("fail write FormInfoFilter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // call private GetFormsInfo with Message which will send request to tell stub which handle function to be used.
    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO, data, formInfos);
    // formInfos should have been fulfilled at this point.
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetAllFormsInfo:%{public}d", error);
    }

    return error;
}

int32_t FormMgrProxy::GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write to formId error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int error = GetPublishedFormInfoById(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID, data, formInfo);
    // formInfos should have been fulfilled at this point.
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetPublishedFormInfoById:%{public}d", error);
    }

    return error;
}

int32_t FormMgrProxy::GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int error = GetPublishedFormInfos(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFOS, data, formInfos);
    // formInfos should have been fulfilled at this point.
    if (error != ERR_OK) {
        HILOG_ERROR("fail GetPublishedFormInfos:%{public}d", error);
    }

    return error;
}

bool FormMgrProxy::IsRequestPublishFormSupported()
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return false;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    // retrieve and return result.
    return reply.ReadBool();
}

int32_t FormMgrProxy::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in want
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in callerToken
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_START_ABILITY,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::StartAbilityByFms(const Want &want)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in want
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_START_ABILITY_BY_FMS,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::StartAbilityByCrossBundle(const Want &want)
{
    HILOG_INFO("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    // write in want
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_START_ABILITY_BY_CROSS_BUNDLE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
    int64_t requestCode)
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

    if (!data.WriteString(deviceId)) {
        HILOG_ERROR("fail write deviceId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write requestCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_SHARE_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("write requestCode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(IFormMgr::Message::FORM_MGR_ACQUIRE_DATA, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }

    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read replyResult failed");
        return error;
    }
    std::shared_ptr<AAFwk::WantParams> wantParams(reply.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOG_ERROR("ReadParcelable<wantParams> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    formData = *wantParams;
    return ERR_OK;
}

int32_t FormMgrProxy::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&info)) {
        HILOG_ERROR("fail write form share info");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::CheckFMSReady()
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_CHECK_FMS_READY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    // retrieve and return result;
    return reply.ReadInt32();
}

bool FormMgrProxy::IsSystemAppForm(const std::string &bundleName)
{
    MessageParcel data;
    // write in token to help identify which stub to be called
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_IS_SYSTEM_APP_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

int32_t FormMgrProxy::SetBackgroundFunction(const std::string funcName, const std::string params)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called
    if (!data.WriteString16(Str8ToStr16(funcName))) {
        HILOG_ERROR("write funcName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(params))) {
        HILOG_ERROR("write params failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("get remoteObject failed");
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int error = remote->SendRequest(Constants::EVENT_CALL_NOTIFY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    // retrieve and return result;
    return reply.ReadInt32();
}

int32_t FormMgrProxy::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_INFO("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isTempFormFlag)) {
        HILOG_ERROR("write bool isEnableUpdate failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    int32_t result = reply.ReadInt32();
    formCount = reply.ReadInt32();
    return result;
}

ErrCode FormMgrProxy::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("RegisterFormAddObserverByBundle start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("error to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_INFO("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    int32_t result = reply.ReadInt32();
    formCount = reply.ReadInt32();
    return result;
}

int32_t FormMgrProxy::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&formInstancesFilter)) {
        HILOG_ERROR("fail write formInstancesFilter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto error = GetFormInstance(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER, data, formInstances);
    if (error != ERR_OK) {
        HILOG_ERROR("fail get form instances by filter:%{public}d", error);
    }

    return error;
}

ErrCode FormMgrProxy::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("GetFormInstanceById start");
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
    auto error = GetParcelableInfo<FormInstance>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID,
        data, formInstance);
    if (error != ERR_OK) {
        HILOG_ERROR("get parcelable info failed");
    }

    return error;
}

ErrCode FormMgrProxy::GetFormInstanceById(const int64_t formId, bool isUnusedInclude, FormInstance &formInstance)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("write isUnusedInclude failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto error = GetParcelableInfo<FormInstance>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID,
        data, formInstance);
    if (error != ERR_OK) {
        HILOG_ERROR("get parcelable info failed");
    }

    return error;
}

ErrCode FormMgrProxy::GetFormInstance(IFormMgr::Message code, MessageParcel &data,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("GetFormInstance start");
    int error;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    error = SendTransactCmd(code, data, reply, option);
    if (error != ERR_OK) {
        return error;
    }
    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("read replyResult failed");
        return error;
    }
    auto ret = GetParcelableInfos<FormInstance>(reply, formInstances);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail get parcelable infos");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ret;
}

ErrCode FormMgrProxy::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("error to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("error to write callerToken");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("error to SendRequest:%{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UpdateProxyForm(int64_t formId, const FormProviderData &FormProviderData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&FormProviderData)) {
        HILOG_ERROR("write formBindingData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("write formDataProxies failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("fail SendTransactCmd");
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RequestPublishProxyForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies)
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
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("write withFormBindingData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("write formBindingData failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (!WriteFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("write formDataProxies failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("fail SendTransactCmd");
        return error;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode == ERR_OK) {
        formId = reply.ReadInt64();
    }
    return errCode;
}

bool FormMgrProxy::WriteFormDataProxies(MessageParcel &data, const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("proxies size:%{public}zu", formDataProxies.size());
    if (!data.WriteInt32(formDataProxies.size())) {
        HILOG_ERROR("fail marshalling form data proxies size");
        return false;
    }
    for (const auto &formDataProxy : formDataProxies) {
        if (!data.WriteString16(Str8ToStr16(formDataProxy.key))) {
            HILOG_ERROR("fail marshalling formDataProxy key:%{public}s", formDataProxy.key.c_str());
            return false;
        }
        if (!data.WriteString16(Str8ToStr16(formDataProxy.subscribeId))) {
            HILOG_ERROR("fail marshalling formDataProxy subscribeId:%{public}s",
                formDataProxy.subscribeId.c_str());
            return false;
        }
    }
    return true;
}

int32_t FormMgrProxy::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in interceptor
    if (!data.WriteRemoteObject(interceptorCallback)) {
        HILOG_ERROR("error to write interceptor");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in interceptor
    if (!data.WriteRemoteObject(interceptorCallback)) {
        HILOG_ERROR("fail write interceptor");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Click callback event start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(formEventType)) {
        HILOG_ERROR("write formEventType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(observer)) {
        HILOG_ERROR("fail write observer");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    return ERR_OK;
}

ErrCode FormMgrProxy::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Click callback event start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(formEventType)) {
        HILOG_ERROR("write formEventType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(observer)) {
        HILOG_ERROR("fail write observer");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    return ERR_OK;
}

int32_t FormMgrProxy::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_SET_FORMS_RECYCLABLE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RECYCLE_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write vector formIds failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RECOVER_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(formLocation)) {
        HILOG_ERROR("fail write formLocation");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_UPDATE_FORM_LOCATION, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("write withFormBindingData failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("write formBindingData failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageOption option;
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode == ERR_OK) {
        formId = reply.ReadInt64();
    }
    return errCode;
}

int32_t FormMgrProxy::BatchRefreshForms(const int32_t formRefreshType)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(formRefreshType)) {
        HILOG_ERROR("fail write formRefreshType");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_BATCH_REFRESH_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::EnableForms(const std::string bundleName, const int32_t userId, const bool enable)
{
    HILOG_DEBUG("EnableForms start.%{public}s", bundleName.c_str());
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        HILOG_ERROR("write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(enable)) {
        HILOG_ERROR("fail write enable");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_ENABLE_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    return ERR_OK;
}

bool FormMgrProxy::IsFormBundleForbidden(const std::string &bundleName)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return true;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return true;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_FORBIDDEN, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

int32_t FormMgrProxy::LockForms(const std::vector<FormLockInfo> &formLockInfos, OHOS::AppExecFwk::LockChangeType type)
{
    HILOG_DEBUG("LockForms start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (formLockInfos.size() > static_cast<size_t>(MAX_ALLOW_SIZE)) {
        HILOG_ERROR("The vector/array size exceeds the security limit!");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    data.WriteInt32(formLockInfos.size());
    for (auto it = formLockInfos.begin(); it != formLockInfos.end(); ++it) {
        if (!data.WriteParcelable(&(*it))) {
            HILOG_ERROR("Write [(*it)] failed!");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    data.WriteInt32(static_cast<int32_t>(type));

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_LOCK_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::IsFormBundleProtected(const std::string &bundleName, int64_t formId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return true;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return true;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("fail write formId ");
        return true;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_PEOTECTED, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

bool FormMgrProxy::IsFormBundleDebugSignature(const std::string &bundleName)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("write bundleName failed");
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_DEBUG_SIGNATURE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

bool FormMgrProxy::IsFormBundleExempt(int64_t formId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return true;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("fail write formId ");
        return true;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_EXEMPT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

int32_t FormMgrProxy::NotifyFormLocked(const int64_t &formId, bool isLocked)
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
    if (!data.WriteBool(isLocked)) {
        HILOG_ERROR("fail write bool isLocked");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_NOTIFY_FORM_LOCKED,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("read reply result failed");
        return result;
    }
    return result;
}

ErrCode FormMgrProxy::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
    float formViewScale)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("fail write formId ");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteFloat(width)) {
        HILOG_ERROR("fail write width");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteFloat(height)) {
        HILOG_ERROR("fail write height");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteFloat(borderWidth)) {
        HILOG_ERROR("fail write borderWidth");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteFloat(formViewScale)) {
        HILOG_ERROR("fail write formViewScale");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_UPDATE_FORM_SIZE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        HILOG_ERROR("fail write abilityName ");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("fail write formId ");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isMainPage)) {
        HILOG_ERROR("fail write isMainPage ");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_OPEN_FORM_EDIT_ABILITY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendTransactCmd:%{public}d failed", error);
        return error;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return false;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("Write callerToken failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(IFormMgr::Message::FORM_MGR_REGISTER_OVERFLOW_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest: %{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

bool FormMgrProxy::UnregisterOverflowProxy()
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_OVERFLOW_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

ErrCode FormMgrProxy::RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow)
{
    HILOG_INFO("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("Write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&overflowInfo)) {
        HILOG_ERROR("Write overflowInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isOverflow)) {
        HILOG_ERROR("Write isOverflow failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(IFormMgr::Message::FORM_MGR_REQUEST_OVERFLOW, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest failed: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("write callerToken failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

bool FormMgrProxy::UnregisterChangeSceneAnimationStateProxy()
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

ErrCode FormMgrProxy::ChangeSceneAnimationState(const int64_t formId, int32_t state)
{
    HILOG_INFO("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("Write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(state)) {
        HILOG_ERROR("Write state failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_CHANGE_SCENE_ANIMATION_STATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest failed: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token");
        return false;
    }
 
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("Failed to write callerToken");
        return false;
    }
 
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_GET_FORM_RECT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return false;
    }
    return reply.ReadBool();
}

bool FormMgrProxy::UnregisterGetFormRectProxy()
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_GET_FORM_RECT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}
 
ErrCode FormMgrProxy::GetFormRect(const int64_t formId, Rect &rect)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
 
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("Failed to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
 
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_GET_FORM_RECT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    error = reply.ReadInt32();
    if (error != ERR_OK) {
        HILOG_ERROR("Read reply result fail: %{public}d", error);
        return error;
    }
    std::unique_ptr<Rect> result(reply.ReadParcelable<Rect>());
    if (!result) {
        HILOG_ERROR("Failed to get parcelable info");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    rect = *result;
    return ERR_OK;
}

ErrCode FormMgrProxy::UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
{
    HILOG_INFO("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("Write formId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(newDimension)) {
        HILOG_ERROR("Write newDimension failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&newRect)) {
        HILOG_ERROR("Write newRect failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(IFormMgr::Message::FORM_MGR_NOTIFY_UPDATE_FORM_SIZE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest failed: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token");
        return false;
    }
 
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("Failed to write callerToken");
        return false;
    }
 
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_REGISTER_GET_LIVE_FORM_STATUS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return false;
    }
    return reply.ReadBool();
}
 
bool FormMgrProxy::UnregisterGetLiveFormStatusProxy()
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
 
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_GET_LIVE_FORM_STATUS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}

ErrCode FormMgrProxy::ReloadForms(int32_t &reloadNum, const std::string &moduleName, const std::string &abilityName,
    const std::string &formName)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        HILOG_ERROR("Write moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        HILOG_ERROR("Write abilityName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(formName)) {
        HILOG_ERROR("Write formName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RELOAD_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest failed: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    reloadNum = reply.ReadInt32();
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::ReloadAllForms(int32_t &reloadNum)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write interface token failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    ErrCode error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RELOAD_ALL_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest failed: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    reloadNum = reply.ReadInt32();
    return reply.ReadInt32();
}

bool FormMgrProxy::IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    if (!data.WriteParcelable(&formMajorInfo)) {
        HILOG_ERROR("Write formMajorInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isDisablePolicy)) {
        HILOG_ERROR("write isDisablePolicy failed");
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_IS_FORM_DUE_CONTROL, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("SendRequest:%{public}d failed", error);
        return false;
    }
    return reply.ReadBool();
}
}  // namespace AppExecFwk
}  // namespace OHOS
