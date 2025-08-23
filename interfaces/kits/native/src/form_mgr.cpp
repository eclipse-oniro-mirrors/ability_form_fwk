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

#include "form_mgr.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_caller_mgr.h"
#ifdef NO_RUNTIME_EMULATOR
#include "form_event_hiappevent.h"
#endif
#include "form_errors.h"
#include "form_event_report.h"
#include "form_mgr_errors.h"
#include "running_form_info.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {

FormMgr::FormMgr()
{
    HILOG_DEBUG("call");
}

FormMgr::~FormMgr()
{
    HILOG_INFO("call");
    if (remoteProxy_ != nullptr) {
        auto remoteObject = remoteProxy_->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

/**
 * @brief Get the error message by error code.
 * @param errorCode the error code return form fms.
 * @return Returns the error message detail.
 */
std::string FormMgr::GetErrorMsg(int errorCode)
{
    return "unknown error";
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param formId The Id of the forms to add.
 * @param want The want of the form to add.
 * @param callerToken Caller ability token.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::AddForm(
    const int64_t formId,
    const Want &want,
    const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    // Perform read lock control. Do not assign a value to remoteProxy_ in subsequent operations.
    std::shared_lock<std::shared_mutex> lock(connectMutex_);

    // To prevent the obtained value of remoteProxy_ from being null,
    // the system checks whether the value of remoteProxy_ is null.
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    errCode = remoteProxy_->AddForm(formId, want, callerToken, formInfo);
    if (errCode != ERR_OK && errCode != ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS &&
        errCode != ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS) {
        // The fault of card quantity exceeds the limit is not reported here
        FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED,
            formInfo.formId,
            formInfo.bundleName,
            formInfo.formName,
            static_cast<int32_t>(AddFormFailedErrorType::ADD_FORM_FAILED),
            errCode);
    }
    return errCode;
}

/**
 * @brief Add form with want, send want to form manager service.
 * @param want The want of the form to add.
 * @param runningFormInfo Running form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    HILOG_INFO("call");
    int resultCode = Connect();
    if (resultCode != ERR_OK) {
        HILOG_ERROR("Connect failed errCode:%{public}d", resultCode);
        return resultCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    resultCode = remoteProxy_->CreateForm(want, runningFormInfo);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("createForm failed,errorCode is %{public}d", resultCode);
    }
    HILOG_INFO("formId:%{public}s", std::to_string(runningFormInfo.formId).c_str());
    return resultCode;
}

/**
 * @brief Delete forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to delete.
 * @param callerToken Caller ability token.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    // check fms recover status
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("delete form failed,form in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    // check formId
    if (formId <= 0) {
        HILOG_ERROR("delete form failed,the passed in formId can't be negative or zero");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    FormCallerMgr::GetInstance().RemoveFormHostCaller(formId);
    return remoteProxy_->DeleteForm(formId, callerToken);
}

/**
 * @brief Stop rendering form.
 * @param formId The Id of the forms to delete.
 * @param compId The compId of the forms to delete.
 * @return Returns ERR_OK on success, others on failure.
*/
int FormMgr::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    // check fms recover status
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    // check formId
    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("invalid formId or empty compId");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->StopRenderingForm(formId, compId);
}

/**
 * @brief Release forms with formIds, send formIds to form manager service.
 * @param formId The Id of the forms to release.
 * @param callerToken Caller ability token.
 * @param delCache Delete Cache or not.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    HILOG_INFO("formId:%{public}" PRId64 ", delCache:%{public}d", formId, delCache);
    // check fms recover status
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    // check formId
    if (formId <= 0) {
        HILOG_ERROR("the passed in formId can't be negative or zero");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    FormCallerMgr::GetInstance().RemoveFormHostCaller(formId);
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->ReleaseForm(formId, callerToken, delCache);
}

/**
 * @brief Update form with formId, send formId to form manager service.
 * @param formId The Id of the form to update.
 * @param formBindingData Form binding data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::UpdateForm(const int64_t formId, const FormProviderData &formBindingData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("UpdateForm failed, form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    if (formId <= 0) {
        HILOG_ERROR(" UpdateForm failed, the passed in formId can't be negative or zero");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    // check formBindingData
    if (formBindingData.GetDataString().empty() && formDataProxies.empty()) {
        HILOG_ERROR("UpdateForm failed,null formProviderData");
        return ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }

    auto hostCaller = FormCallerMgr::GetInstance().GetFormHostCaller(formId);
    if (hostCaller != nullptr) {
        hostCaller->UpdateForm(formId, formBindingData);
    } else {
        std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers;
        FormCallerMgr::GetInstance().GetFormProviderCaller(formId, formProviderCallers);
        for (const auto &formProviderCaller : formProviderCallers) {
            formProviderCaller->UpdateForm(formId, formBindingData);
        }
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    if (formDataProxies.empty()) {
        return remoteProxy_->UpdateForm(formId, formBindingData);
    }
    return remoteProxy_->UpdateProxyForm(formId, formBindingData, formDataProxies);
}

/**
 * @brief Release renderer.
 * @param formId The Id of the forms to release.
 * @param compId The compId of the forms to release.
 * @return Returns ERR_OK on success, others on failure.
*/
int FormMgr::ReleaseRenderer(const int64_t formId, const std::string &compId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    // check fms recover status
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    // check formId and compId
    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("invalid formId or empty compId");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->ReleaseRenderer(formId, compId);
}

/**
 * @brief Notify the form service that the form user's lifecycle is updated.
 *
 * This should be called when form user request form.
 *
 * @param formId Indicates the unique id of form.
 * @param callerToken Indicates the callback remote object of specified form user.
 * @param want information passed to supplier.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgr::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    auto hostCaller = FormCallerMgr::GetInstance().GetFormHostCaller(formId);
    if (hostCaller != nullptr) {
        HILOG_INFO("request by host caller");
        return hostCaller->RequestForm(formId, callerToken, want);
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->RequestForm(formId, callerToken, want);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail notify the form service that the form user's lifecycle is updated"
            "code is %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Form visible/invisible notify, send formIds to form manager service.
 * @param formIds The Id list of the forms to notify.
 * @param callerToken Caller ability token.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::NotifyWhetherVisibleForms(
    const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken,
    const int32_t formVisibleType)
{
    HILOG_DEBUG("formVisibleType is %{public}d", formVisibleType);

    if (formIds.empty() || formIds.size() > Constants::MAX_VISIBLE_NOTIFY_LIST) {
        HILOG_ERROR("empty formIds or exceed 32");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    // IPC entry
    ErrCode resultCode = remoteProxy_->NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("internal error occurs,errCode:%{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Query whether has visible form by tokenId.
 * @param tokenId Unique identification of application.
 * @return Returns true if has visible form, false otherwise.
 */
bool FormMgr::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->HasFormVisible(tokenId);
}

/**
 * @brief temp form to normal form.
 * @param formId The Id of the form.
 * @param callerToken Caller ability token.
 * @return None.
 */
int FormMgr::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0) {
        HILOG_ERROR("passing in form id can't be negative");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->CastTempForm(formId, callerToken);
}

/**
 * @brief Dump all of form storage infos.
 * @param formInfos All of form storage infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DumpStorageFormInfos(std::string &formInfos)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->DumpStorageFormInfos(formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param bundleName The bundle name of form provider.
 * @param formInfos Form infos.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DumpFormInfoByBundleName(const std::string bundleName, std::string &formInfos)
{
    HILOG_INFO("bundleName is %{public}s", bundleName.c_str());
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->DumpFormInfoByBundleName(bundleName, formInfos);
}
/**
 * @brief Dump form info by a bundle name.
 * @param formId The id of the form.
 * @param formInfo Form info.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->DumpFormInfoByFormId(formId, formInfo);
}
/**
 * @brief Dump form timer by form id.
 * @param formId The id of the form.
 * @param formInfo Form timer.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService)
{
    HILOG_INFO("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->DumpFormTimerByFormId(formId, isTimingService);
}
/**
 * @brief Process js message event.
 * @param formId Indicates the unique id of form.
 * @param want information passed to supplier.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgr::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    auto hostCaller = FormCallerMgr::GetInstance().GetFormHostCaller(formId);
    if (hostCaller != nullptr) {
        HILOG_DEBUG("send message by host caller");
        return hostCaller->MessageEvent(formId, want, callerToken);
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->MessageEvent(formId, want, callerToken);
}

/**
 * @brief Process js router event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgr::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RouterEvent(formId, want, callerToken);
}

/**
 * @brief Process Background event.
 * @param formId Indicates the unique id of form.
 * @param want the want of the ability to start.
 * @param callerToken Caller ability token.
 * @return Returns true if execute success, false otherwise.
 */
int FormMgr::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->BackgroundEvent(formId, want, callerToken);
}

/**
 * @brief Set next refresh time.
 * @param formId The id of the form.
 * @param nextTime Next refresh time.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_INFO("call, nextTime:%{public}" PRId64 ", formId:%{public}" PRId64, nextTime, formId);

    if (GetInstance().GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("formManager is in recovering");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->SetNextRefreshTime(formId, nextTime);
}

ErrCode FormMgr::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_INFO("call");
#ifdef NO_RUNTIME_EMULATOR
    int64_t processorId = FormEventHiAppEvent::AddProcessor();
    HILOG_INFO("Add processor begin.Processor id is %{public}" PRId64, processorId);
    time_t beginTime = time(nullptr);
#endif
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    if (formDataProxies.empty()) {
        return remoteProxy_->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    }
    ErrCode ret = remoteProxy_->RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
#ifdef NO_RUNTIME_EMULATOR
    PublishFormData publishFormData = {
    want.GetElement().GetBundleName(),
    want.GetElement().GetAbilityName(),
    want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, -1),
    want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
    want.GetStringParam(Constants::PARAM_FORM_NAME_KEY)};
    FormEventHiAppEvent::WriteAppFormEndEvent(ret, beginTime, "RequestPublishForm", publishFormData, processorId);
#endif
    return ret;
}


ErrCode FormMgr::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    HILOG_INFO("call");
    if (formId <= 0) {
        HILOG_ERROR("errCode:%{public}." PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->SetPublishFormResult(formId, errorCodeInfo);
}

ErrCode FormMgr::AcquireAddFormResult(const int64_t formId)
{
    HILOG_INFO("call");
    if (formId <= 0) {
        HILOG_ERROR("errCode:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->AcquireAddFormResult(formId);
}

int FormMgr::LifecycleUpdate(
    const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken,
    bool updateType)
{
    HILOG_INFO("call");

    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->LifecycleUpdate(formIds, callerToken, updateType);
}
/**
 * @brief Get fms recoverStatus.
 *
 * @return The current recover status.
 */
int FormMgr::GetRecoverStatus()
{
    HILOG_DEBUG("get recover status");
    return recoverStatus_;
}

/**
 * @brief Set fms recoverStatus.
 *
 * @param recoverStatus The recover status.
 */
void FormMgr::SetRecoverStatus(int recoverStatus)
{
    HILOG_INFO("call");
    recoverStatus_ = recoverStatus;
}

/**
 * @brief Get the error message content.
 *
 * @param errCode Error code.
 * @return Message content.
 */
std::string FormMgr::GetErrorMessage(int errCode)
{
    HILOG_INFO("call");
    return FormErrors::GetInstance().GetErrorMessage(errCode);
}

/**
 * @brief Register death callback.
 *
 * @param deathCallback Death callback.
 */
void FormMgr::RegisterDeathCallback(const std::shared_ptr<FormCallbackInterface> &formDeathCallback)
{
    HILOG_INFO("call");
    if (formDeathCallback == nullptr) {
        HILOG_ERROR("null formDeathCallback");
        return;
    }
    formDeathCallbacks_.emplace_back(formDeathCallback);
}

/**
 * @brief UnRegister death callback.
 *
 * @param deathCallback Death callback.
 */
void FormMgr::UnRegisterDeathCallback(const std::shared_ptr<FormCallbackInterface> &formDeathCallback)
{
    HILOG_INFO("call");
    if (formDeathCallback == nullptr) {
        HILOG_ERROR("null formDeathCallback");
        return;
    }

    // Remove the specified death callback in the vector of death callback
    auto iter = std::find(formDeathCallbacks_.begin(), formDeathCallbacks_.end(), formDeathCallback);
    if (iter != formDeathCallbacks_.end()) {
        formDeathCallbacks_.erase(iter);
    }
    HILOG_INFO("end");
}

/**
 * @brief Get death recipient.
 * @return deathRecipient_.
 */
sptr<IRemoteObject::DeathRecipient> FormMgr::GetDeathRecipient() const
{
    return deathRecipient_;
}

/**
 * @brief Check whether the specified death callback is registered in form mgr.
 * @param formDeathCallback The specified death callback for checking.
 * @return Return true on success, false on failure.
 */
bool FormMgr::CheckIsDeathCallbackRegistered(const std::shared_ptr<FormCallbackInterface> &formDeathCallback)
{
    HILOG_INFO("call");
    auto iter = std::find(formDeathCallbacks_.begin(), formDeathCallbacks_.end(), formDeathCallback);
    if (iter != formDeathCallbacks_.end()) {
        return true;
    }
    return false;
}

/**
 * @brief Notices IRemoteBroker died.
 * @param remote remote object.
 */
void FormMgr::FormMgrDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("call");
    if (remote == nullptr) {
        HILOG_ERROR("null remote");
        return;
    }

    if (FormMgr::GetInstance().GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_WARN("fms in recovering");
        return;
    }
    // Reset proxy
    FormMgr::GetInstance().ResetProxy(remote);

    if (!FormMgr::GetInstance().Reconnect()) {
        HILOG_ERROR("form mgr service died,try to reconnect to fms failed");
        FormMgr::GetInstance().SetRecoverStatus(Constants::RECOVER_FAIL);
        return;
    }

    // refresh form host.
    for (auto &deathCallback : FormMgr::GetInstance().formDeathCallbacks_) {
        deathCallback->OnDeathReceived();
    }
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
}

/**
 * @brief Reconnect form manager service once per 1000 milliseconds,
 *        until the connection succeeds or reaching the max retry times.
 * @return Returns true if execute success, false otherwise.
 */
bool FormMgr::Reconnect()
{
    HILOG_DEBUG("call");
    for (int i = 0; i < Constants::MAX_RETRY_TIME; i++) {
        // Sleep 1000 milliseconds before reconnect.
        std::this_thread::sleep_for(std::chrono::milliseconds(Constants::SLEEP_TIME));

        // try to connect fms
        if (Connect() != ERR_OK) {
            HILOG_ERROR("get fms proxy fail,try again");
            continue;
        }

        HILOG_INFO("success");
        return true;
    }

    return false;
}

/**
 * @brief Connect form manager service.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormMgr::Connect()
{
    {
        std::shared_lock<std::shared_mutex> lock(connectMutex_);
        if (remoteProxy_ != nullptr && !resetFlag_) {
            return ERR_OK;
        }
    }
    {
        std::lock_guard<std::shared_mutex> lock(connectMutex_);
        sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemManager == nullptr) {
            HILOG_ERROR("get registry failed");
            return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
        }
        sptr<IRemoteObject> remoteObject = systemManager->GetSystemAbility(FORM_MGR_SERVICE_ID);
        if (remoteObject == nullptr) {
            HILOG_ERROR("connect FormMgrService failed");
            return ERR_APPEXECFWK_FORM_GET_FMS_FAILED;
        }
        deathRecipient_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) FormMgrDeathRecipient());
        if (deathRecipient_ == nullptr) {
            HILOG_ERROR("null deathRecipient_");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        if ((remoteObject->IsProxyObject()) && (!remoteObject->AddDeathRecipient(deathRecipient_))) {
            HILOG_ERROR("fail add death recipient to FormMgrService");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        remoteProxy_ = iface_cast<IFormMgr>(remoteObject);
        if (remoteProxy_ == nullptr) {
            HILOG_ERROR("null remoteProxy_");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        HILOG_DEBUG("Connecting FormMgrService success");
        return ERR_OK;
    }
}

/**
 * @brief Reset proxy.
 * @param remote remote object.
 */
void FormMgr::ResetProxy(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return;
    }

    // set formMgr's recover status to IN_RECOVERING.
    recoverStatus_ = Constants::IN_RECOVERING;

    // remove the death recipient
    auto serviceRemote = remoteProxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
    }
    // clearn the remote proxy
    remoteProxy_ = nullptr;
}

/**
 * @brief Set form mgr service for test.
 */
void FormMgr::SetFormMgrService(sptr<IFormMgr> formMgrService)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::shared_mutex> lock(connectMutex_);
    remoteProxy_ = formMgrService;
}

/**
 * @brief Delete the invalid forms.
 * @param formIds Indicates the ID of the valid forms.
 * @param callerToken Host client.
 * @param numFormsDeleted Returns the number of the deleted forms.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                int32_t &numFormsDeleted)
{
    HILOG_DEBUG("call");
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail DeleteInvalidForms,errCode %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
 * @param want Indicates a set of parameters to be transparently passed to the form provider.
 * @param callerToken Host client.
 * @param stateInfo Returns the form's state info of the specify.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo)
{
    HILOG_DEBUG("call");
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->AcquireFormState(want, callerToken, stateInfo);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail AcquireFormState,errCode %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Notify the form is visible or not.
 * @param formIds Indicates the ID of the forms.
 * @param isVisible Visible or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->NotifyFormsVisible(formIds, isVisible, callerToken);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail NotifyFormsVisible,errCode %{public}d", resultCode);
    }
    return resultCode;
}

int FormMgr::NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                         const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->NotifyFormsPrivacyProtected(formIds, isProtected, callerToken);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail NotifyFormsPrivacyProtected,errCode %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Notify the form is enable to be updated or not.
 * @param formIds Indicates the ID of the forms.
 * @param isEnableUpdate enable update or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                     const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail NotifyFormsEnableUpdate,errCode %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Get All FormsInfo.
 * @param formInfos Return the forms' information of all forms provided.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->GetAllFormsInfo(formInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetAllFormsInfo,errCode %{public}d", resultCode);
    }
    return resultCode;
}

/**
 * @brief Get forms info by bundle name .
 * @param bundleName Application name.
 * @param formInfos Return the forms' information of the specify application name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("bundleName is %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        HILOG_WARN("fail Get forms info,because empty bundle name");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }

    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->GetFormsInfoByApp(bundleName, formInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByApp,errCode %{public}d", resultCode);
    }
    return resultCode;
}
/**
 * @brief Get forms info by bundle name and module name.
 * @param bundleName bundle name.
 * @param moduleName Module name of hap.
 * @param formInfos Return the forms' information of the specify bundle name and module name.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgr::GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
    std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("bundleName is %{public}s, moduleName is %{public}s", bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty()) {
        HILOG_WARN("fail Get forms info,because empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }

    if (moduleName.empty()) {
        HILOG_WARN("fail Get forms info,because empty moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_MODULENAME;
    }

    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->GetFormsInfoByModule(bundleName, moduleName, formInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByModule,errCode %{public}d", resultCode);
    }
    return resultCode;
}

int FormMgr::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->GetFormsInfoByFilter(filter, formInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetFormsInfoByFilter,errCode %{public}d", resultCode);
    }
    return resultCode;
}

int32_t FormMgr::GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetFormsInfo(filter, formInfos);
}

int32_t FormMgr::GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetPublishedFormInfoById(formId, formInfo);
}

int32_t FormMgr::GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos)
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetPublishedFormInfos(formInfos);
}

bool FormMgr::IsRequestPublishFormSupported()
{
    HILOG_DEBUG("call");
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->IsRequestPublishFormSupported();
}

int32_t FormMgr::StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->StartAbility(want, callerToken);
}

int32_t FormMgr::StartAbilityByFms(const Want &want)
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->StartAbilityByFms(want);
}

int32_t FormMgr::StartAbilityByCrossBundle(const Want &want)
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    auto ret = remoteProxy_->StartAbilityByCrossBundle(want);
    if (ret == ERR_APPEXECFWK_FORM_NOT_TRUST) {
        return ERR_FORM_EXTERNAL_PERMISSION_DENIED;
    } else if (ret == ERR_APPEXECFWK_FORM_GET_HOST_FAILED || ret == ERR_APPEXECFWK_FORM_COMMON_CODE) {
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
    }
    return ret;
}

int32_t FormMgr::ShareForm(int64_t formId, const std::string &remoteDeviceId,
    const sptr<IRemoteObject> &callerToken, int64_t requestCode)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->ShareForm(formId, remoteDeviceId, callerToken, requestCode);
}

int32_t FormMgr::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->AcquireFormData(formId, requestCode, callerToken, formData);
}

bool FormMgr::CheckFMSReady()
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    bool resultCode = remoteProxy_->CheckFMSReady();
    if (resultCode == false) {
        HILOG_ERROR("CheckFMSReady failed");
    }
    return resultCode;
}

bool FormMgr::IsSystemAppForm(const std::string &bundleName)
{
    HILOG_DEBUG("check %{public}s is system form", bundleName.c_str());
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->IsSystemAppForm(bundleName);
}

int32_t FormMgr::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("register publish form failed, errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterPublishFormInterceptor(interceptorCallback);
}

int32_t FormMgr::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->UnregisterPublishFormInterceptor(interceptorCallback);
}

void FormMgr::GetExternalError(int32_t innerErrorCode, int32_t &externalErrorCode, std::string &errorMsg)
{
    externalErrorCode = FormErrors::GetInstance().QueryExternalErrorCode(innerErrorCode);
    errorMsg = FormErrors::GetInstance().QueryExternalErrorMessage(innerErrorCode, externalErrorCode);
    HILOG_DEBUG("innerErrorCode:%{public}d, externalErrorCode:%{public}d, errorMsg:%{public}s",
        innerErrorCode, externalErrorCode, errorMsg.c_str());
}

std::string FormMgr::GetErrorMsgByExternalErrorCode(int32_t externalErrorCode)
{
    return FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(externalErrorCode);
}

ErrCode FormMgr::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_INFO("isUnusedIncluded is %{public}d", isUnusedIncluded);
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetRunningFormInfos,errCode %{public}d", resultCode);
    }
    return resultCode;
}

ErrCode FormMgr::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("bundleName is %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        HILOG_WARN("fail Get running form infos,because empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->GetRunningFormInfosByBundleName(
        bundleName, isUnusedIncluded, runningFormInfos);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetRunningFormInfosByBundleName,errCode %{public}d", resultCode);
    }
    return resultCode;
}

ErrCode FormMgr::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("bundleName is %{public}s", bundleName.c_str());
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterFormAddObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgr::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("bundleName is %{public}s", bundleName.c_str());
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
}

int32_t FormMgr::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_INFO("isTempFormFlag is %{public}d", isTempFormFlag);

    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int32_t resultCode = remoteProxy_->GetFormsCount(isTempFormFlag, formCount);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetFormsCount,errCode %{public}d", resultCode);
    }
    return resultCode;
}

int32_t FormMgr::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_DEBUG("bundleName is %{public}s", bundleName.c_str());

    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    if (bundleName.empty()) {
        HILOG_WARN("fail Get host forms count,because empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }

    int32_t errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int32_t resultCode = remoteProxy_->GetHostFormsCount(bundleName, formCount);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail GetFormsCount,errCode %{public}d", resultCode);
    }
    return resultCode;
}

ErrCode FormMgr::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("call");
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgr::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("formId is %{public}" PRId64, formId);
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgr::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    HILOG_DEBUG("formId is %{public}" PRId64, formId);
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgr::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("bundleName is %{public}s", bundleName.c_str());
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterAddObserver(bundleName, callerToken);
}

ErrCode FormMgr::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("bundleName is %{public}s", bundleName.c_str());
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterRemoveObserver(bundleName, callerToken);
}

ErrCode FormMgr::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("empty callerTokenParameter");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterClickEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgr::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("empty callerTokenParameter");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->UnregisterClickEventObserver(bundleName, formEventType, observer);
}

int FormMgr::RegisterFormRouterProxy(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RegisterFormRouterProxy(formIds, callerToken);
#else
    return ERR_OK;
#endif
}

int FormMgr::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status,can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->UnregisterFormRouterProxy(formIds);
}

int32_t FormMgr::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->SetFormsRecyclable(formIds);
}

int32_t FormMgr::RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("call");
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RecycleForms(formIds, want);
}

int32_t FormMgr::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("call");
    if (GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    auto errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->RecoverForms(formIds, want);
}

ErrCode FormMgr::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->UpdateFormLocation(formId, formLocation);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail UpdateFormLocation,errCode %{public}d", resultCode);
    }
    return resultCode;
}

ErrCode FormMgr::RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_INFO("call");
#ifdef NO_RUNTIME_EMULATOR
    int64_t processorId = FormEventHiAppEvent::AddProcessor();
    HILOG_INFO("Add processor begin.Processor id is %{public}" PRId64, processorId);
    time_t beginTime = time(nullptr);
#endif
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode ret = remoteProxy_->RequestPublishFormWithSnapshot(want, withFormBindingData,
        formBindingData, formId);
#ifdef NO_RUNTIME_EMULATOR
    PublishFormData publishFormData = {
    want.GetElement().GetBundleName(),
    want.GetElement().GetAbilityName(),
    want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, -1),
    want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
    want.GetStringParam(Constants::PARAM_FORM_NAME_KEY)};
    FormEventHiAppEvent::WriteAppFormEndEvent(ret, beginTime, "RequestPublishFormWithSnapshot",
        publishFormData, processorId);
#endif
    return ret;
}

int32_t FormMgr::BatchRefreshForms(const int32_t formRefreshType)
{
    HILOG_INFO("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("BatchRefreshForms failed, form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    if (formRefreshType < Constants::REFRESH_ALL_FORM || formRefreshType > Constants::REFRESH_ATOMIC_FORM) {
        HILOG_ERROR("BatchRefreshForms failed, invalid formRefreshType %{public}d", formRefreshType);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("errCode:%{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->BatchRefreshForms(formRefreshType);
}

int32_t FormMgr::EnableForms(const std::string bundleName, const bool enable)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->EnableForms(bundleName, enable);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail EnableForms,errCode %{public}d", resultCode);
    }
    return resultCode;
}

bool FormMgr::IsFormBundleForbidden(const std::string &bundleName)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->IsFormBundleForbidden(bundleName);
}

bool FormMgr::IsFormBundleProtected(const std::string &bundleName, int64_t formId)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->IsFormBundleProtected(bundleName, formId);
}

bool FormMgr::IsFormBundleExempt(int64_t formId)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->IsFormBundleExempt(formId);
}

ErrCode FormMgr::UpdateFormSize(const int64_t formId, float width, float height, float borderWidth)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode resultCode = remoteProxy_->UpdateFormSize(formId, width, height, borderWidth);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail UpdateFormSize,errCode %{public}d", resultCode);
    }
    return resultCode;
}

int32_t FormMgr::NotifyFormLocked(const int64_t &formId, bool isLocked)
{
    HILOG_DEBUG("call");
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("form is in recover status, can't do action on form");
        return ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
    }

    int errCode = Connect();
    if (errCode != ERR_OK) {
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int resultCode = remoteProxy_->NotifyFormLocked(formId, isLocked);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail NotifyFormLocked, errCode %{public}d", resultCode);
    }
    return resultCode;
}

ErrCode FormMgr::OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage)
{
    HILOG_INFO("abilityName: %{public}s, formId: %{public}" PRId64 ", isMainPage: %{public}s",
        abilityName.c_str(), formId, isMainPage ? "true" : "false");
    ErrCode resultCode = Connect();
    if (resultCode != ERR_OK) {
        return resultCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    resultCode = remoteProxy_->OpenFormEditAbility(abilityName, formId, isMainPage);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail OpenFormEditAbility,errCode %{public}d", resultCode);
    }
    return resultCode;
}

bool FormMgr::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("Call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("Connect form mgr service failed, errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->RegisterOverflowProxy(callerToken);
}

bool FormMgr::UnregisterOverflowProxy()
{
    HILOG_INFO("call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->UnregisterOverflowProxy();
}

ErrCode FormMgr::RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow)
{
    HILOG_INFO("Call");
    if (formId <= 0) {
        HILOG_ERROR("RequestOverflow failed, formId is invalid");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    if (isOverflow && overflowInfo.duration <= 0) {
        HILOG_ERROR("RequestOverflow failed, duration is invalid");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("Connect form mgr service failed, errCode %{public}d", errCode);
        return errCode;
    }

    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("remoteProxy_ is invalid");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ErrCode result = remoteProxy_->RequestOverflow(formId, overflowInfo, isOverflow);
    HILOG_INFO("RequestOverflow result: %{public}d", result);
    return result;
}

bool FormMgr::RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->RegisterChangeSceneAnimationStateProxy(callerToken);
}

bool FormMgr::UnregisterChangeSceneAnimationStateProxy()
{
    HILOG_INFO("call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->UnregisterChangeSceneAnimationStateProxy();
}

ErrCode FormMgr::ChangeSceneAnimationState(const int64_t formId, int32_t state)
{
    HILOG_INFO("call");
    if (formId <= 0) {
        HILOG_ERROR("RequestOverflow failed, formId is invalid");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed, errCode %{public}d", errCode);
        return errCode;
    }

    // check remoteProxy_
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ErrCode result = remoteProxy_->ChangeSceneAnimationState(formId, state);
    HILOG_INFO("ChangeSceneAnimationState result: %{public}d", result);
    return result;
}

bool FormMgr::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->RegisterGetFormRectProxy(callerToken);
}

bool FormMgr::UnregisterGetFormRectProxy()
{
    HILOG_INFO("call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->UnregisterGetFormRectProxy();
}
 
ErrCode FormMgr::GetFormRect(const int64_t formId, Rect &rect)
{
    if (formId <= 0) {
        HILOG_ERROR("empty formId");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    int errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return errCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return remoteProxy_->GetFormRect(formId, rect);
}

ErrCode FormMgr::UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
{
    HILOG_INFO("UpdateFormSize formid:%{public}" PRId64, formId);
    if (formId <= 0) {
        HILOG_ERROR("UpdateFormSize failed, formId is invalid");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    ErrCode resultCode = Connect();
    if (resultCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed, errCode %{public}d", resultCode);
        return resultCode;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    resultCode = remoteProxy_->UpdateFormSize(formId, newDimension, newRect);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("fail UpdateFormSize,errCode %{public}d", resultCode);
    }
    return resultCode;
}

bool FormMgr::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->RegisterGetLiveFormStatusProxy(callerToken);
}
 
bool FormMgr::UnregisterGetLiveFormStatusProxy()
{
    HILOG_INFO("call");
    ErrCode errCode = Connect();
    if (errCode != ERR_OK) {
        HILOG_ERROR("connect form mgr service failed,errCode %{public}d", errCode);
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(connectMutex_);
    if (remoteProxy_ == nullptr) {
        HILOG_ERROR("null remoteProxy_");
        return false;
    }
    return remoteProxy_->UnregisterGetLiveFormStatusProxy();
}
}  // namespace AppExecFwk
}  // namespace OHOS
