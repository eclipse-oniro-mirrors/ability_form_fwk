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

#include "form_mgr/form_callback_adapter.h"

#include "app_mgr_interface.h"
#include "app_state_data.h"
#include "form_info.h"
#include "iform_host_delegate.h"
#include "iform_provider_delegate.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/form_cust_config_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/route_proxy/form_router_proxy_mgr.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr/form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_event_report.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormCallbackAdapter::FormCallbackAdapter(FormCommonAdapter* commonAdapter)
    : commonAdapter_(commonAdapter)
{
}

ErrCode FormCallbackAdapter::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<int64_t> matchedFormIds {};
    std::vector<int64_t> hostOwnFormIds {};
    auto uid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(uid);
    FormRecord record;
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("FormId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        auto matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_ERROR("No matching formRecord was found for formId:%{public}" PRId64 "", formId);
            continue;
        }
        matchedFormIds.push_back(formId);

        if (record.providerUserId != userId) {
            HILOG_ERROR("formId:%{public}" PRId64" correspond to a card is not for the currently active user.", formId);
            continue;
        } else if (std::find(record.formUserUids.begin(),
            record.formUserUids.end(), uid) == record.formUserUids.end()) {
            HILOG_ERROR("The formId:%{public}" PRId64 " owned by other formHost", formId);
            continue;
        } else {
            HILOG_DEBUG("The setup was successful, matchedFormIds:%{public}" PRId64 "", formId);
            hostOwnFormIds.push_back(formId);
        }
    }
    if (matchedFormIds.empty()) {
        HILOG_ERROR("invalid formIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (hostOwnFormIds.empty()) {
        HILOG_ERROR("All formIds were not set by self");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    return FormRouterProxyMgr::GetInstance().SetFormRouterProxy(hostOwnFormIds, callerToken);
#else
    return ERR_OK;
#endif
}

ErrCode FormCallbackAdapter::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> matchedFormIds {};
    std::vector<int64_t> hostOwnFormIds {};
    auto uid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(uid);
    FormRecord record;
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("FormId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        auto matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_ERROR("No matching formRecord was found for formId:%{public}" PRId64 "", formId);
            continue;
        }
        matchedFormIds.push_back(formId);

        if (record.providerUserId != userId) {
            HILOG_ERROR("The formId:%{public}" PRId64
                        " corresponds to a card that is not for the currently active user.", formId);
            continue;
        } else if (std::find(record.formUserUids.begin(),
            record.formUserUids.end(), uid) == record.formUserUids.end()) {
            HILOG_ERROR("The formId:%{public}" PRId64 " owned by other formHost", formId);
            continue;
        } else {
            HILOG_DEBUG("The setup was successful, matchedFormIds:%{public}" PRId64 "", formId);
            hostOwnFormIds.push_back(formId);
        }
    }
    if (matchedFormIds.empty()) {
        HILOG_ERROR("invalid formIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (hostOwnFormIds.empty()) {
        HILOG_ERROR("All formIds were not set by self");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    return FormRouterProxyMgr::GetInstance().RemoveFormRouterProxy(hostOwnFormIds);
}

ErrCode FormCallbackAdapter::RegisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    if (interceptorCallback == nullptr) {
        HILOG_ERROR("null interceptorCallback");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    if (interceptor == nullptr) {
        HILOG_ERROR("RegisterPublishFormInterceptor failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(formPublishInterceptorMutex_);
    formPublishInterceptor_ = interceptor;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    if (interceptorCallback == nullptr) {
        HILOG_ERROR("null interceptorCallback");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    if (interceptor == nullptr) {
        HILOG_ERROR("UnregisterPublishFormInterceptor failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(formPublishInterceptorMutex_);
    if (formPublishInterceptor_ == interceptor) {
        HILOG_DEBUG("UnregisterPublishFormInterceptor success");
        formPublishInterceptor_ = nullptr;
        return ERR_OK;
    }
    HILOG_ERROR("the param not equal to current interceptor");
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormCallbackAdapter::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    std::lock_guard<std::mutex> lock(overflowCallerTokenMutex_);
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    overflowCallerToken_ = callerToken;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterOverflowProxy()
{
    std::lock_guard<std::mutex> lock(overflowCallerTokenMutex_);
    HILOG_INFO("call");
    overflowCallerToken_ = nullptr;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    std::lock_guard<std::mutex> lock(overflowCallerTokenMutex_);
    HILOG_INFO("call");
    ErrCode checkResult = SceneAnimationCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(overflowCallerToken_);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("Failed, remoteFormHostDelegateProxy is nullptr");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    ErrCode result = remoteFormHostDelegateProxy->RequestOverflow(formId, overflowInfo, isOverflow);
    HILOG_INFO("RequestOverflow result: %{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterChangeSceneAnimationStateProxy(
    const sptr<IRemoteObject> &callerToken)
{
    std::lock_guard<std::mutex> lock(sceneanimationCallerTokenMutex_);
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    sceneanimationCallerToken_ = callerToken;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterChangeSceneAnimationStateProxy()
{
    std::lock_guard<std::mutex> lock(sceneanimationCallerTokenMutex_);
    HILOG_INFO("call");
    sceneanimationCallerToken_ = nullptr;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::ChangeSceneAnimationState(const int64_t formId,
    const int32_t callingUid, int32_t state)
{
    std::lock_guard<std::mutex> lock(sceneanimationCallerTokenMutex_);
    HILOG_INFO("call");
    ErrCode checkResult = SceneAnimationCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(sceneanimationCallerToken_);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("Fail, remoteFormHostDelegateProxy is nullptr!");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    ErrCode result = remoteFormHostDelegateProxy->ChangeSceneAnimationState(formId, state);
    HILOG_INFO("ChangeSceneAnimationState result: %{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SetFormRectCallerToken(callerToken);
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterGetFormRectProxy()
{
    HILOG_INFO("call");
    ClearFormRectCallerToken();
    return ERR_OK;
}

ErrCode FormCallbackAdapter::GetFormRect(const int64_t formId,
    const int32_t callingUid, Rect &rect)
{
    HILOG_INFO("call");
    ErrCode checkResult = CallerCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    sptr<IRemoteObject> formRectCallerToken = GetFormRectCallerToken();
    if (formRectCallerToken == nullptr) {
        HILOG_ERROR("Fail, formRectCallerToken_ is nullptr!");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(formRectCallerToken);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("Fail, remoteFormHostDelegateProxy is nullptr!");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    ErrCode result = remoteFormHostDelegateProxy->GetFormRect(formId, rect);

    HILOG_DEBUG("GetFormRect, result:%{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SetLiveFormStatusCallerToken(callerToken);
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterGetLiveFormStatusProxy()
{
    HILOG_INFO("call");
    ClearLiveFormStatusCallerToken();
    return ERR_OK;
}

ErrCode FormCallbackAdapter::GetLiveFormStatus(
    std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    HILOG_INFO("call");
    sptr<IRemoteObject> liveFormStatusCallerToken = GetLiveFormStatusCallerToken();
    if (liveFormStatusCallerToken == nullptr) {
        HILOG_ERROR("Fail, liveFormStatusCallerToken_ is nullptr!");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(liveFormStatusCallerToken);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("Fail, remoteFormHostDelegateProxy is nullptr!");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    ErrCode result = remoteFormHostDelegateProxy->GetLiveFormStatus(liveFormStatusMap);

    HILOG_INFO("GetLiveFormStatus, result:%{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterPublishFormCrossBundleControl(
    const sptr<IRemoteObject> &callerToken)
{
    std::lock_guard<std::mutex> lock(crossBundleControlCallerTokenMutex_);
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    crossBundleControlCallerToken_ = callerToken;
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterPublishFormCrossBundleControl()
{
    std::lock_guard<std::mutex> lock(crossBundleControlCallerTokenMutex_);
    HILOG_INFO("call");
    crossBundleControlCallerToken_ = nullptr;
    return ERR_OK;
}

bool FormCallbackAdapter::PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo)
{
    std::lock_guard<std::mutex> lock(crossBundleControlCallerTokenMutex_);
    HILOG_INFO("call, callerBundleName:%{public}s, targetBundleName:%{public}s, targetTemplateFormDetailId:%{public}s,",
        bundleInfo.callerBundleName.c_str(), bundleInfo.targetBundleName.c_str(),
        bundleInfo.targetTemplateFormDetailId.c_str());
    if (!crossBundleControlCallerToken_) {
        HILOG_ERROR("Fail, crossBundleControlCallerToken_ is nullptr!");
        return false;
    }
    sptr<IFormProviderDelegate> remoteFormProviderDelegateProxy =
        iface_cast<IFormProviderDelegate>(crossBundleControlCallerToken_);
    if (remoteFormProviderDelegateProxy == nullptr) {
        HILOG_ERROR("Fail, remoteFormProviderDelegateProxy is nullptr!");
        return false;
    }
    bool isCanOpen = false;
    ErrCode result = remoteFormProviderDelegateProxy->PublishFormCrossBundleControl(bundleInfo, isCanOpen);
    HILOG_INFO("result:%{public}d, isCanOpen:%{public}d", result, isCanOpen);
    return (result == ERR_OK) ? isCanOpen : false;
}

ErrCode FormCallbackAdapter::RegisterTemplateFormDetailInfoChange(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SetTemplateFormDetailInfoCallerToken(callerToken);
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UnregisterTemplateFormDetailInfoChange()
{
    HILOG_INFO("call");
    ClearTemplateFormDetailInfoCallerToken();
    return ERR_OK;
}

ErrCode FormCallbackAdapter::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    HILOG_DEBUG("r");
    auto templateFormDetailInfoCallerToken = GetTemplateFormDetailInfoCallerToken();
    if (templateFormDetailInfoCallerToken == nullptr) {
        HILOG_ERROR("failed, templateFormDetailInfoCallerToken_ is nullptr!");
        return ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy =
        iface_cast<IFormHostDelegate>(templateFormDetailInfoCallerToken);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("failed, remoteFormHostDelegateProxy is nullptr!");
        return ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION;
    }

    ErrCode result = remoteFormHostDelegateProxy->TemplateFormDetailInfoChange(templateFormInfo);

    HILOG_DEBUG("update result:%{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::CallerCheck(const int64_t formId, const int32_t callingUid)
{
    HILOG_INFO("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    if (formRecord.providerUserId != userId) {
        HILOG_ERROR("not self form:%{public}" PRId64 ", callingUid:%{public}d", formId, callingUid);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    return ERR_OK;
}

ErrCode FormCallbackAdapter::SceneAnimationCheck(const int64_t formId, const int32_t callingUid)
{
    HILOG_INFO("call");
    ErrCode checkResult = CallerCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    if (!FormCustConfigMgr::GetInstance().IsSupportSceneAnimation()) {
        HILOG_ERROR("fms not support sceneAnimation of live form");
        return ERR_APPEXECFWK_SYSTEMCAP_ERROR;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    bool isBundleProtect = FormBundleLockMgr::GetInstance().IsBundleProtect(formRecord.bundleName, userId, formId);
    if (isBundleProtect) {
        HILOG_ERROR("Failed, application is locked");
        return ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED;
    }
    Want want;
    want.SetElementName(formRecord.bundleName, formRecord.abilityName);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, formRecord.moduleName);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formRecord.formName);
    FormInfo formInfo;
    ErrCode errCode = commonAdapter_->GetFormInfo(want, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get target form info failed");
        return errCode;
    }
    if (formInfo.sceneAnimationParams.abilityName.empty()) {
        HILOG_ERROR("SceneAnimationParams abilityName is empty");
        return ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED;
    }
    return ERR_OK;
}

void FormCallbackAdapter::SetFormRectCallerToken(const sptr<IRemoteObject> formRectCallerToken)
{
    HILOG_INFO("call");
    if (formRectCallerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return;
    }
    std::lock_guard<std::mutex> lock(formRectCallerTokenMutex_);
    formRectCallerToken_ = formRectCallerToken;
}

void FormCallbackAdapter::ClearFormRectCallerToken()
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(formRectCallerTokenMutex_);
    formRectCallerToken_ = nullptr;
}

sptr<IRemoteObject> FormCallbackAdapter::GetFormRectCallerToken()
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formRectCallerTokenMutex_);
    return formRectCallerToken_;
}

void FormCallbackAdapter::SetLiveFormStatusCallerToken(const sptr<IRemoteObject> liveFormStatusCallerToken)
{
    HILOG_INFO("call");
    if (liveFormStatusCallerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return;
    }
    std::lock_guard<std::mutex> lock(liveFormStatusCallerTokenMutex_);
    liveFormStatusCallerToken_ = liveFormStatusCallerToken;
}

void FormCallbackAdapter::ClearLiveFormStatusCallerToken()
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(liveFormStatusCallerTokenMutex_);
    liveFormStatusCallerToken_ = nullptr;
}

sptr<IRemoteObject> FormCallbackAdapter::GetLiveFormStatusCallerToken()
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(liveFormStatusCallerTokenMutex_);
    return liveFormStatusCallerToken_;
}

void FormCallbackAdapter::SetTemplateFormDetailInfoCallerToken(
    const sptr<IRemoteObject> templateFormDetailInfoCallerToken)
{
    HILOG_INFO("call");
    if (templateFormDetailInfoCallerToken == nullptr) {
        HILOG_ERROR("callerToken is null");
        return;
    }
    std::lock_guard<std::mutex> lock(templateFormDetailInfoCallerTokenMutex_);
    templateFormDetailInfoCallerToken_ = templateFormDetailInfoCallerToken;
}

void FormCallbackAdapter::ClearTemplateFormDetailInfoCallerToken()
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(templateFormDetailInfoCallerTokenMutex_);
    templateFormDetailInfoCallerToken_ = nullptr;
}

sptr<IRemoteObject> FormCallbackAdapter::GetTemplateFormDetailInfoCallerToken()
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(templateFormDetailInfoCallerTokenMutex_);
    return templateFormDetailInfoCallerToken_;
}

void FormCallbackAdapter::SetFormPublishInterceptor(const sptr<IFormPublishInterceptor> &interceptor)
{
    std::lock_guard<std::mutex> lock(formPublishInterceptorMutex_);
    formPublishInterceptor_ = interceptor;
}

sptr<IFormPublishInterceptor> FormCallbackAdapter::GetFormPublishInterceptor()
{
    std::lock_guard<std::mutex> lock(formPublishInterceptorMutex_);
    return formPublishInterceptor_;
}

ErrCode FormCallbackAdapter::StartAbilityByFms(const Want &want)
{
    Want wantToHost(want);
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    wantToHost.SetParam(Constants::PARAM_FORM_USER_ID, userId);

    int32_t pageRouterServiceCode = want.GetIntParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE, -1);
    HILOG_DEBUG("StartAbilityByFms pageRouterServiceCode: %{public}" PRId32, pageRouterServiceCode);
    if (pageRouterServiceCode == Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE) {
        HILOG_DEBUG("StartAbilityByFms getForegroundApplications begin");
        bool isForeground = IsForegroundApp();
        if (!isForeground) {
            HILOG_ERROR("This application is not a foreground program");
            return ERR_APPEXECFWK_FORM_NOT_TRUST;
        }
        HILOG_DEBUG("This application is a foreground program");
    } else if (pageRouterServiceCode == Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM) {
        HILOG_DEBUG("support launcher check start");
        std::unordered_map<std::string, std::string> liveFormStatusMap;
        GetLiveFormStatus(liveFormStatusMap);
        const std::string formId = want.GetStringParam(Constants::PARAM_LIVE_FORM_ID_KEY);
        auto it = liveFormStatusMap.find(formId);
        if (it == liveFormStatusMap.end()) {
            HILOG_ERROR("This live form is non-existent, formId:%{public}s", formId.c_str());
            return ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED;
        }
        std::string status = it->second;
        auto iter = Constants::LIVE_FORM_STATUS_MAP.find(status);
        if (iter == Constants::LIVE_FORM_STATUS_MAP.end() || !iter->second.isSupportLauncher) {
            HILOG_ERROR("This live form is not support launcher, status:%{public}s", status.c_str());
            return ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED;
        }
        HILOG_DEBUG("support launcher check success");
    }

    ElementName elementName = want.GetElement();
    std::string dstBundleName = elementName.GetBundleName();
    std::string dstAbilityName = elementName.GetAbilityName();
    wantToHost.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, dstBundleName);
    wantToHost.SetParam(Constants::PARAM_ABILITY_NAME_KEY, dstAbilityName);

    HILOG_INFO("dstBundleName:%{public}s, dstAbilityName:%{public}s",
        dstBundleName.c_str(), dstAbilityName.c_str());

    // Query ability info by action
    std::string action = Constants::FORM_PUBLISH_ACTION;
    if (!wantToHost.GetAction().empty()) {
        action = wantToHost.GetAction();
        HILOG_INFO("GetAction:%{public}s", action.c_str());
    }

    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        action, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("fail ImplicitQueryInfoByPriority for publishing form");
        if (want.GetStringParam(Constants::PARMA_REQUEST_METHOD) == Constants::OPEN_FORM_MANAGE_VIEW) {
            FormEventReport::SendRequestPublicFormEvent(dstBundleName, "",
                RequestFormType::OPEN_FORM_MANAGER);
        }
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    if (!abilityInfo.name.empty()) {
        HILOG_DEBUG("Query highest priority ability success. bundleName:%{public}s, ability:%{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        wantToHost.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    } else if (!extensionAbilityInfo.name.empty()) {
        HILOG_DEBUG("Query highest priority extension ability success. bundleName:%{public}s, ability:%{public}s",
            extensionAbilityInfo.bundleName.c_str(), extensionAbilityInfo.name.c_str());
        wantToHost.SetElementName(extensionAbilityInfo.bundleName, extensionAbilityInfo.name);
    } else {
        HILOG_ERROR("Query highest priority ability failed, no form host ability found");
        if (want.GetStringParam(Constants::PARMA_REQUEST_METHOD) == Constants::OPEN_FORM_MANAGE_VIEW) {
            FormEventReport::SendRequestPublicFormEvent(dstBundleName, "",
                RequestFormType::OPEN_FORM_MANAGER);
        }
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    HILOG_INFO("StartAbility wantToHost:%{public}s", wantToHost.ToString().c_str());
    return FormAmsHelper::GetInstance().StartAbility(wantToHost, userId);
}

bool FormCallbackAdapter::IsForegroundApp()
{
    bool checkFlag = false;
    std::string bundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return false;
    }
    auto appMgrProxy = commonAdapter_->GetAppMgr();
    if (!appMgrProxy) {
        HILOG_ERROR("Get app mgr failed");
        return false;
    }
    std::vector<AppExecFwk::AppStateData> curForegroundApps;
    IN_PROCESS_CALL_WITHOUT_RET(appMgrProxy->GetForegroundApplications(curForegroundApps));
    for (auto &appData : curForegroundApps) {
        HILOG_DEBUG("appData.bundleName: %{public}s", appData.bundleName.c_str());
        if (appData.bundleName == bundleName) {
            checkFlag = true;
            break;
        }
    }
    return checkFlag;
}

} // namespace AppExecFwk
} // namespace OHOS
