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
#include "form_mgr/form_publish_adapter.h"
#include "form_mgr_errors.h"
#include "form_event_report.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormCallbackAdapter::FormCallbackAdapter()
{
    HILOG_DEBUG("FormCallbackAdapter created");
}

FormCallbackAdapter::~FormCallbackAdapter()
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
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return overflowRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterOverflowProxy()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return overflowRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    HILOG_INFO("call");
    ErrCode checkResult = SceneAnimationCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64, matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    ErrCode result = ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    for (int uid : formRecord.formUserUids) {
        sptr<IRemoteObject> callerToken;
        if (overflowRegistry_.Get(uid, callerToken) != ERR_OK) {
            continue;
        }
        sptr<IFormHostDelegate> proxy = iface_cast<IFormHostDelegate>(callerToken);
        if (proxy == nullptr) {
            continue;
        }
        result = proxy->RequestOverflow(formId, overflowInfo, isOverflow);
    }
    HILOG_INFO("RequestOverflow result: %{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterChangeSceneAnimationStateProxy(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return sceneAnimationRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterChangeSceneAnimationStateProxy()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return sceneAnimationRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::ChangeSceneAnimationState(const int64_t formId,
    const int32_t callingUid, int32_t state)
{
    HILOG_INFO("call");
    ErrCode checkResult = SceneAnimationCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64, matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    ErrCode result = ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    for (int uid : formRecord.formUserUids) {
        sptr<IRemoteObject> callerToken;
        if (sceneAnimationRegistry_.Get(uid, callerToken) != ERR_OK) {
            continue;
        }
        sptr<IFormHostDelegate> proxy = iface_cast<IFormHostDelegate>(callerToken);
        if (proxy == nullptr) {
            continue;
        }
        result = proxy->ChangeSceneAnimationState(formId, state);
        if (result == ERR_OK) {
            break;
        }
    }
    HILOG_INFO("ChangeSceneAnimationState result: %{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return formRectRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterGetFormRectProxy()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return formRectRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::GetFormRect(const int64_t formId,
    const int32_t callingUid, Rect &rect)
{
    HILOG_INFO("call");
    ErrCode checkResult = CallerCheck(formId, callingUid);
    if (checkResult != ERR_OK) {
        return checkResult;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64, matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    ErrCode result = ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    for (int uid : formRecord.formUserUids) {
        sptr<IRemoteObject> callerToken;
        if (formRectRegistry_.Get(uid, callerToken) != ERR_OK) {
            continue;
        }
        sptr<IFormHostDelegate> proxy = iface_cast<IFormHostDelegate>(callerToken);
        if (proxy == nullptr) {
            continue;
        }
        result = proxy->GetFormRect(formId, rect);
        if (result == ERR_OK) {
            break;
        }
    }
    HILOG_DEBUG("GetFormRect, result:%{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return liveFormStatusRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterGetLiveFormStatusProxy()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return liveFormStatusRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::GetLiveFormStatus(
    std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    HILOG_INFO("call");
    std::vector<sptr<IRemoteObject>> callerTokens;
    ErrCode ret = liveFormStatusRegistry_.GetAll(callerTokens);
    if (ret != ERR_OK) {
        return ret;
    }
    ErrCode result = ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    for (const auto &callerToken : callerTokens) {
        sptr<IFormHostDelegate> proxy = iface_cast<IFormHostDelegate>(callerToken);
        if (proxy == nullptr) {
            continue;
        }
        std::unordered_map<std::string, std::string> partialMap;
        ErrCode proxyResult = proxy->GetLiveFormStatus(partialMap);
        if (proxyResult == ERR_OK) {
            result = ERR_OK;
            liveFormStatusMap.insert(partialMap.begin(), partialMap.end());
        }
    }
    HILOG_INFO("GetLiveFormStatus, result:%{public}d", result);
    return result;
}

ErrCode FormCallbackAdapter::RegisterPublishFormCrossBundleControl(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return crossBundleControlRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterPublishFormCrossBundleControl()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return crossBundleControlRegistry_.Unregister(callingUid);
}

bool FormCallbackAdapter::PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo)
{
    HILOG_INFO("call, callerBundleName:%{public}s, targetBundleName:%{public}s, targetTemplateFormDetailId:%{public}s,",
        bundleInfo.callerBundleName.c_str(), bundleInfo.targetBundleName.c_str(),
        bundleInfo.targetTemplateFormDetailId.c_str());
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    std::vector<sptr<IRemoteObject>> callerTokens;
    ErrCode ret = crossBundleControlRegistry_.GetByUserId(userId, callerTokens);
    if (ret != ERR_OK) {
        return false;
    }
    // All proxies must approve for cross-bundle control to pass
    for (const auto &callerToken : callerTokens) {
        sptr<IFormProviderDelegate> remoteFormProviderDelegateProxy =
            iface_cast<IFormProviderDelegate>(callerToken);
        if (remoteFormProviderDelegateProxy == nullptr) {
            HILOG_ERROR("Failed to cast IFormProviderDelegate");
            continue;
        }
        bool isCanOpen = false;
        ErrCode result = remoteFormProviderDelegateProxy->PublishFormCrossBundleControl(bundleInfo, isCanOpen);
        HILOG_INFO("result:%{public}d, isCanOpen:%{public}d", result, isCanOpen);
        if (result != ERR_OK || !isCanOpen) {
            return false;
        }
    }
    return true;
}

ErrCode FormCallbackAdapter::RegisterTemplateFormDetailInfoChange(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return templateFormDetailInfoRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterTemplateFormDetailInfoChange()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return templateFormDetailInfoRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    HILOG_DEBUG("call");
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    std::vector<sptr<IRemoteObject>> callerTokens;
    ErrCode ret = templateFormDetailInfoRegistry_.GetByUserId(userId, callerTokens);
    if (ret != ERR_OK) {
        return ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION;
    }
    ErrCode result = ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION;
    for (const auto &callerToken : callerTokens) {
        sptr<IFormHostDelegate> remoteFormHostDelegateProxy =
            iface_cast<IFormHostDelegate>(callerToken);
        if (remoteFormHostDelegateProxy == nullptr) {
            HILOG_ERROR("failed, remoteFormHostDelegateProxy is nullptr!");
            continue;
        }
        ErrCode ret = remoteFormHostDelegateProxy->TemplateFormDetailInfoChange(templateFormInfo);
        HILOG_DEBUG("update result:%{public}d", ret);
        if (ret == ERR_OK) {
            result = ERR_OK;
        }
    }
    return result;
}

ErrCode FormCallbackAdapter::RegisterUpdateFormsConfigCallback(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    ErrCode result = updateFormsConfigRegistry_.Register(callingUid, callerToken);
    if (result == ERR_OK) {
        NotifyCachedFormConfigs(callerToken);
    }
    return result;
}

ErrCode FormCallbackAdapter::UnregisterUpdateFormsConfigCallback()
{
    HILOG_INFO("call");
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    return updateFormsConfigRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::UpdateFormsConfig(const std::vector<FormCustomConfig> &configs)
{
    HILOG_DEBUG("call, config size: %{public}zu", configs.size());
    {
        std::lock_guard<std::mutex> lock(formCustomConfigCacheMutex_);
        formCustomConfigCache_ = configs;
    }
    ErrCode persistResult = FormInfoMgr::GetInstance().UpdateFormShowConfigs(configs);
    if (persistResult != ERR_OK) {
        HILOG_ERROR("UpdateFormShowConfigs failed, err:%{public}d", persistResult);
    }
    ErrCode notifyResult = NotifyAllHosts(updateFormsConfigRegistry_, "UpdateFormsConfig",
        [&configs](const sptr<IFormHostDelegate> &proxy) {
            return proxy->UpdateFormsConfigCallback(configs);
        });
    return notifyResult != ERR_OK ? notifyResult : persistResult;
}

ErrCode FormCallbackAdapter::NotifyAllHosts(FormProxyRegistry &registry, const std::string &tag,
    const std::function<ErrCode(const sptr<IFormHostDelegate> &)> &callback)
{
    std::vector<std::pair<int32_t, sptr<IRemoteObject>>> entries;
    ErrCode ret = registry.GetAllWithKeys(entries);
    if (ret != ERR_OK) {
        HILOG_WARN("no host registered for %{public}s", tag.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    ErrCode result = ERR_OK;
    for (const auto &[callingUid, callerToken] : entries) {
        int32_t userId = FormUtil::GetCallerUserId(callingUid);
        std::string bundleName;
        FormBmsHelper::GetInstance().GetBundleNameByUid(callingUid, bundleName);
        sptr<IFormHostDelegate> proxy = iface_cast<IFormHostDelegate>(callerToken);
        if (proxy == nullptr) {
            HILOG_ERROR("iface_cast failed, %{public}s, userId=%{public}d, bundleName=%{public}s",
                tag.c_str(), userId, bundleName.c_str());
            result = ERR_APPEXECFWK_FORM_COMMON_CODE;
            continue;
        }
        ErrCode notifyRet = callback(proxy);
        if (notifyRet != ERR_OK) {
            HILOG_ERROR("notify failed, %{public}s, userId=%{public}d, bundleName=%{public}s, ret=%{public}d",
                tag.c_str(), userId, bundleName.c_str(), notifyRet);
            result = ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    HILOG_INFO("%{public}s notified %{public}zu hosts, result=%{public}d", tag.c_str(), entries.size(), result);
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
    if (formRecord.uid != callingUid) {
        HILOG_ERROR("not match providerUid:%{public}d and callingUid:%{public}d", formRecord.uid, callingUid);
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
    ErrCode errCode = FormCommonAdapter::GetInstance().GetFormInfo(want, formInfo);
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

    if (!FormPublishAdapter::GetInstance().IsActionAllowToPublish(action)) {
        HILOG_ERROR("action is not allowed to publish: %{public}s", action.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
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
    auto appMgrProxy = FormCommonAdapter::GetInstance().GetAppMgr();
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

void FormCallbackAdapter::NotifyCachedFormConfigs(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    std::vector<FormCustomConfig> cached;
    {
        std::lock_guard<std::mutex> lock(formCustomConfigCacheMutex_);
        if (formCustomConfigCache_.empty()) {
            HILOG_INFO("no cached form configs");
            return;
        }
        cached = formCustomConfigCache_;
    }
    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(callerToken);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("remoteFormHostDelegateProxy is nullptr");
        return;
    }
    ErrCode ret = remoteFormHostDelegateProxy->UpdateFormsConfigCallback(cached);
    HILOG_INFO("notify cached configs result:%{public}d", ret);
}

ErrCode FormCallbackAdapter::RegisterFormWantCallback(int32_t callingUid, const sptr<IRemoteObject> &callerToken)
{
    return wantCallbackRegistry_.Register(callingUid, callerToken);
}

ErrCode FormCallbackAdapter::UnregisterFormWantCallback(int32_t callingUid)
{
    return wantCallbackRegistry_.Unregister(callingUid);
}

ErrCode FormCallbackAdapter::GetWantCallbackProxy(int32_t callingUid, sptr<IRemoteObject> &proxy)
{
    return wantCallbackRegistry_.Get(callingUid, proxy);
}

} // namespace AppExecFwk
} // namespace OHOS
