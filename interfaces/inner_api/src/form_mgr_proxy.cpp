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
        HILOG_ERROR("%{public}s, write to interface token failed", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, write to formId failed", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, write to want failed", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write to callerTokenfailed", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetParcelableInfo<FormJsInfo>(IFormMgr::Message::FORM_MGR_ADD_FORM, data, formInfo);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("failed to SendRequest: %{public}d", ret);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int FormMgrProxy::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(compId)) {
        HILOG_ERROR("%{public}s, failed to write compId", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(delCache)) {
        HILOG_ERROR("%{public}s, failed to write delCache", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&FormProviderData)) {
        HILOG_ERROR("%{public}s, failed to write formBindingData", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(nextTime)) {
        HILOG_ERROR("%{public}s, failed to write nextTime", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int FormMgrProxy::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
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
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_RELEASE_RENDERER,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("%{public}s, failed to write withFormBindingData", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("%{public}s, failed to write formBindingData", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(errorCodeInfo.message)) {
        HILOG_ERROR("%{public}s, failed to write ErrorCode message", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(errorCodeInfo.code))) {
        HILOG_ERROR("%{public}s, failed to write ErrorCode", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageOption option;
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::AcquireAddFormResult(const int64_t formId)
{
    MessageParcel data;
    MessageParcel reply;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_ACQUIRE_ADD_FORM_RESULT,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(updateType)) {
        HILOG_ERROR("%{public}s, failed to write nextTime", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
    HILOG_INFO("%{public}s called.", __func__);

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write formIds", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(formVisibleType)) {
        HILOG_ERROR("%{public}s, failed to write formVisibleType", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
    HILOG_DEBUG("called.");

    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, error to write interface token", __func__);
        return false;
    }
    if (!data.WriteUint32(tokenId)) {
        HILOG_ERROR("%{public}s, failed to write tokenId", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, callerToken is write failed", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetStringInfo: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetStringInfo: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID, data, formInfo);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetStringInfo: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetStringInfo(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID, data, isTimingService);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetStringInfo: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, error to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, error to write callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, write failed to interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, write failed to formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, write failed to want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write failed to callerToken", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, write to interface token error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, write to formId error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, write to want error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write to callerToken error", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(IFormMgr::Message::FORM_MGR_ROUTER_EVENT,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

template<typename T>
int  FormMgrProxy::GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    int32_t infoSize = reply.ReadInt32();
    if (infoSize < 0 || infoSize > MAX_ALLOW_SIZE) {
        HILOG_ERROR("%{public}s invalid size = %{public}d", __func__, infoSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (!info) {
            HILOG_ERROR("%{public}s, error to Read Parcelable infos", __func__);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
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
        HILOG_ERROR("%{public}s, error to read reply result", __func__);
        return error;
    }
    std::vector<std::string> stringInfoList;
    if (!reply.ReadStringVector(&stringInfoList)) {
        HILOG_ERROR("%{public}s, failed to read string vector from reply", __func__);
        return false;
    }
    if (stringInfoList.empty()) {
        HILOG_INFO("%{public}s, No string info", __func__);
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
        HILOG_ERROR("%{public}s, read reply result fail", __func__);
        return error;
    }

    return GetParcelableInfos<FormInfo>(reply, formInfos);
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
        HILOG_ERROR("failed to read reply result");
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
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
        return error;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (!info) {
        HILOG_ERROR("%{public}s, failed to readParcelableInfo", __func__);
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
        HILOG_ERROR("%{public}s, error to get remote object, cmd: %{public}d", __func__, code);
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, error to SendRequest: %{public}d, cmd: %{public}d", __func__, result, code);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write vector formIds", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, error to write callerToken", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write fail to callerToken", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
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
        HILOG_ERROR("%{public}s, error to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, error to write vector formIds", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isVisible)) {
        HILOG_ERROR("%{public}s, failed to write bool isVisible", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write to callerToken failed ", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
        return result;
    }
    return result;
}

int FormMgrProxy::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                              const sptr<IRemoteObject> &callerToken)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write vector formIds", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isProtected)) {
        HILOG_ERROR("%{public}s, failed to write bool isProtected", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write callerToken error", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("%{public}s, failed to write vector formIds", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnableUpdate)) {
        HILOG_ERROR("%{public}s, failed to write bool isEnableUpdate", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, write error to callerToken", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }

    int32_t result = reply.ReadInt32();
    if (result != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to read reply result", __func__);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetAllFormsInfo: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetFormsInfoByApp: %{public}d", __func__, error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(moduleName)) {
        HILOG_ERROR("%{public}s, failed to write moduleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetFormsInfoByModule: %{public}d", __func__, error);
    }

    return error;
}

int FormMgrProxy::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(filter.bundleName)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(filter.moduleName)) {
        HILOG_ERROR("%{public}s, failed to write moduleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32Vector(filter.supportDimensions)) {
        HILOG_ERROR("Failed to write vector supportDimensions.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32Vector(filter.supportShapes)) {
        HILOG_ERROR("Failed to write vector supportShapes.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER, data, formInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetFormsInfoByFilter: %{public}d", __func__, error);
    }

    return error;
}

ErrCode FormMgrProxy::GetRunningFormInfos(bool isUnusedInclude, std::vector<RunningFormInfo> &runningFormInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("Failed to write isUnusedInclude.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode error = GetRunningFormInfos(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS, data, runningFormInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to GetRunningFormInfos: %{public}d", error);
    }
    return error;
}

ErrCode FormMgrProxy::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedInclude, std::vector<RunningFormInfo> &runningFormInfos)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write bundleName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("Failed to write isUnusedInclude.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode error = GetRunningFormInfos(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE,
        data, runningFormInfos);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to GetRunningFormInfosByBundleName: %{public}d", error);
    }
    return error;
}

int32_t FormMgrProxy::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("%{public}s start.", __func__);
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&filter)) {
        HILOG_ERROR("%{public}s, failed to write FormInfoFilter", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // call private GetFormsInfo with Message which will send request to tell stub which handle function to be used.
    int error = GetFormsInfo(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO, data, formInfos);
    // formInfos should have been fulfilled at this point.
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to GetAllFormsInfo: %{public}d", __func__, error);
    }

    return error;
}

bool FormMgrProxy::IsRequestPublishFormSupported()
{
    HILOG_INFO("%{public}s start.", __func__);
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, error to write interface token", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return false;
    }
    // retrieve and return result.
    return reply.ReadBool();
}

int32_t FormMgrProxy::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s start.", __func__);
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in want
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in callerToken
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("%{public}s, failed to write callerToken", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
    int64_t requestCode)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("error to write formId.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(deviceId)) {
        HILOG_ERROR("failed to write deviceId.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("failed to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("failed to write requestCode.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_SHARE_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("failed to write formId.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt64(requestCode)) {
        HILOG_ERROR("failed to write requestCode.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("failed to write callerToken.");
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
        HILOG_ERROR("failed to read reply result");
        return error;
    }
    std::shared_ptr<AAFwk::WantParams> wantParams(reply.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOG_ERROR("failed to ReadParcelable<wantParams>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    formData = *wantParams;
    return ERR_OK;
}

int32_t FormMgrProxy::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&info)) {
        HILOG_ERROR("failed to write form share info.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

bool FormMgrProxy::CheckFMSReady()
{
    HILOG_DEBUG("%{public}s start.", __func__);
    MessageParcel data;
    // write in token to help identify which stub to be called
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return false;
    }
    // send request
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_CHECK_FMS_READY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return false;
    }
    // retrieve and return result;
    return reply.ReadBool();
}

int32_t FormMgrProxy::SetBackgroundFunction(const std::string funcName, const std::string params)
{
    HILOG_DEBUG("start");
    MessageParcel data;
    // write in token to help identify which stub to be called
    if (!data.WriteString16(Str8ToStr16(funcName))) {
        HILOG_ERROR("failed to write funcName");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString16(Str8ToStr16(params))) {
        HILOG_ERROR("failed to write params");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("failed to get remote object");
        return ERR_APPEXECFWK_SERVICE_NOT_CONNECTED;
    }
    int error = remote->SendRequest(Constants::EVENT_CALL_NOTIFY, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    // retrieve and return result;
    return reply.ReadInt32();
}

int32_t FormMgrProxy::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_INFO("%{public}s start.", __func__);
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isTempFormFlag)) {
        HILOG_ERROR("%{public}s, failed to write bool isEnableUpdate", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    int32_t result = reply.ReadInt32();
    formCount = reply.ReadInt32();
    return result;
}

ErrCode FormMgrProxy::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("RegisterFormAddObserverByBundle start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("error to write bundleName.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("failed to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write bundleName.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("failed to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE,
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_INFO("%{public}s start.", __func__);
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("%{public}s, failed to write bundleName", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    int32_t result = reply.ReadInt32();
    formCount = reply.ReadInt32();
    return result;
}

int32_t FormMgrProxy::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&formInstancesFilter)) {
        HILOG_ERROR("failed to write formInstancesFilter");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto error = GetFormInstance(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER, data, formInstances);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to get form instances by filter: %{public}d", error);
    }

    return error;
}

ErrCode FormMgrProxy::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("GetFormInstanceById start.");
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
        HILOG_ERROR("failed to get parcelable info.");
    }

    return error;
}

ErrCode FormMgrProxy::GetFormInstanceById(const int64_t formId, bool isUnusedInclude, FormInstance &formInstance)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("failed to write formId");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isUnusedInclude)) {
        HILOG_ERROR("Failed to write isUnusedInclude.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto error = GetParcelableInfo<FormInstance>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID,
        data, formInstance);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to get parcelable info.");
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
        HILOG_ERROR("failed to read reply result");
        return error;
    }
    auto ret = GetParcelableInfos<FormInstance>(reply, formInstances);
    if (ret != ERR_OK) {
        HILOG_ERROR("failed to get parcelable infos.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ret;
}

ErrCode FormMgrProxy::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("error to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("error to write bundleName.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("error to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("error to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("failed to write bundleName.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("failed to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("Called.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("Failed to write vector formIds.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(callerToken)) {
        HILOG_ERROR("Failed to write callerToken.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    auto error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("Called.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("Failed to write vector formIds.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option;
    auto error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UpdateProxyForm(int64_t formId, const FormProviderData &FormProviderData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&FormProviderData)) {
        HILOG_ERROR("%{public}s, failed to write formBindingData", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!WriteFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("failed to write form data proxies.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd.");
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("%{public}s, failed to write withFormBindingData", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("%{public}s, failed to write formBindingData", __func__);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (!WriteFormDataProxies(data, formDataProxies)) {
        HILOG_ERROR("failed to write form data proxies.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd.");
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
    HILOG_DEBUG("proxies size: %{public}zu.", formDataProxies.size());
    if (!data.WriteInt32(formDataProxies.size())) {
        HILOG_ERROR("failed to marshalling form data proxies size.");
        return false;
    }
    for (const auto &formDataProxy : formDataProxies) {
        if (!data.WriteString16(Str8ToStr16(formDataProxy.key))) {
            HILOG_ERROR("failed to marshalling form data proxies key: %{public}s.", formDataProxy.key.c_str());
            return false;
        }
        if (!data.WriteString16(Str8ToStr16(formDataProxy.subscribeId))) {
            HILOG_ERROR("failed to marshalling form data proxies subscribeId: %{public}s.",
                formDataProxy.subscribeId.c_str());
            return false;
        }
    }
    return true;
}

int32_t FormMgrProxy::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("start.");
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
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

int32_t FormMgrProxy::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    // write in token to help identify which stub to be called.
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // write in interceptor
    if (!data.WriteRemoteObject(interceptorCallback)) {
        HILOG_ERROR("failed to write interceptor");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    // send request.
    MessageParcel reply;
    MessageOption option;
    int error = SendTransactCmd(
        IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR,
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }
    // retrieve and return result.
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Click callback event start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("Failed to write bundle name.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(formEventType)) {
        HILOG_ERROR("Failed to write form event type.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(observer)) {
        HILOG_ERROR("Failed to write observer.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("Remote object is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    auto error = remote->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return error;
    }
    return ERR_OK;
}

ErrCode FormMgrProxy::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("Click callback event start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Failed to write interface token.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        HILOG_ERROR("Failed to write bundle name.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(formEventType)) {
        HILOG_ERROR("Failed to write form event type.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(observer)) {
        HILOG_ERROR("Failed to write observer.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("Remote object is nullptr.");
        return ERR_INVALID_OPERATION;
    }
    auto error = remote->SendRequest(
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER), data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return error;
    }
    return ERR_OK;
}

int32_t FormMgrProxy::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("failed to write vector formIds.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_SET_FORMS_RECYCLABLE, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd: %{public}d.", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("failed to write vector formIds");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("failed to write want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RECYCLE_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd: %{public}d.", error);
        return error;
    }
    return reply.ReadInt32();
}

int32_t FormMgrProxy::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("failed to write vector formIds");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("failed to write want");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_RECOVER_FORMS, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd: %{public}d.", error);
        return error;
    }
    return reply.ReadInt32();
}

ErrCode FormMgrProxy::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    HILOG_DEBUG("start.");
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("failed to write interface token");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("%{public}s, failed to write formId", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(formLocation)) {
        HILOG_ERROR("failed to write formLocation");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t error = SendTransactCmd(IFormMgr::Message::FORM_MGR_UPDATE_FORM_LOCATION, data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendTransactCmd: %{public}d.", error);
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
        HILOG_ERROR("%{public}s, failed to write interface token", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("%{public}s, failed to write want", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(withFormBindingData)) {
        HILOG_ERROR("%{public}s, failed to write withFormBindingData", __func__);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (withFormBindingData) {
        if (!data.WriteParcelable(formBindingData.get())) {
            HILOG_ERROR("%{public}s, failed to write formBindingData", __func__);
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
        HILOG_ERROR("%{public}s, failed to SendRequest: %{public}d", __func__, error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    ErrCode errCode = reply.ReadInt32();
    if (errCode == ERR_OK) {
        formId = reply.ReadInt64();
    }
    return errCode;
}
}  // namespace AppExecFwk
}  // namespace OHOS
