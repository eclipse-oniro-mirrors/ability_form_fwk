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

#include "form_mgr/form_event_adapter.h"

#include <algorithm>

#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "hitrace_meter.h"
// For the INSIGHT_INTENT_EXECUTE_PARAM_* reserved keys carried in the want; the execute param
// itself uses the lite variant below (AMS no longer parses the want on its side).
#include "insight_intent/insight_intent_execute_param.h"
#include "insight_intent/insight_intent_execute_lite_param.h"
#include "insight_intent_host_client.h"
#include "running_form_info.h"
#include "start_options.h"

#include "nlohmann/json.hpp"

#ifdef DEVICE_USAGE_STATISTICS_ENABLE
#include "bundle_active_client.h"
#endif

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "feature/route_proxy/form_router_proxy_mgr.h"
#include "form_constants.h"
#include "form_host/form_host_record.h"
#include "form_mgr/form_adapter_constants.h"
#include "form_mgr/form_common_adapter.h"
#include "form_observer/form_observer_record.h"
#include "form_provider/connection/form_background_connection.h"
#include "form_provider/form_provider_mgr.h"
#include "json_util_form.h"


namespace OHOS {
namespace AppExecFwk {
using namespace FormAdapterConstants;
namespace {
constexpr int64_t MAX_NUMBER_OF_JS = 0x20000000000000;
constexpr const char* PARAM_FREE_INSTALL_CALLING_UID = "ohos.freeinstall.params.callingUid";

// Get the provider specify token id (hapTokenId) for permission checking; returns 0 on failure.
uint32_t GetProviderSpecifyTokenId(const std::string &bundleName, const int32_t userId)
{
    if (bundleName.empty()) {
        return 0;
    }
    const auto specifyTokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, 0);
    if (specifyTokenId == 0) {
        HILOG_ERROR("GetHapTokenID failed, userId:%{public}d, bundleName:%{public}s",
            userId, bundleName.c_str());
        return 0;
    }
    return specifyTokenId;
}

// The intent execution target is the provider module's entry UIAbility (mainElement in
// module.json5, e.g. EntryAbility), not the FormExtensionAbility providing the form
// (record.abilityName). AMS sets the element with this abilityName and strictly matches
// it with the declared one; backfilling the FormExtensionAbility name causes mismatch.
std::string GetProviderMainElement(const FormRecord &record)
{
    BundleInfo bundleInfo;
    const int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    // Query in the provider's user space; in multi-user scenarios it may differ from the caller user.
    if (!FormBmsHelper::GetInstance().GetBundleInfoByFlags(
        record.bundleName, flags, record.providerUserId, bundleInfo)) {
        HILOG_ERROR("GetBundleInfoByFlags failed, bundleName:%{public}s", record.bundleName.c_str());
        return "";
    }
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.name == record.moduleName) {
            return hapModuleInfo.mainElementName;
        }
    }
    HILOG_ERROR("module not found, bundleName:%{public}s, moduleName:%{public}s",
        record.bundleName.c_str(), record.moduleName.c_str());
    return "";
}

// Extract the intent name and params from the host want into the lite param (AMS reads them
// only from the param on its side) and backfill the provider triple into the want element,
// which AMS reads via want.GetElement(); returns ERR_OK or an error code.
int PrepareInsightIntentParam(Want &want, const FormRecord &record, InsightIntentExecuteLiteParam &executeParam)
{
    const WantParams &wantParams = want.GetParams();
    if (!wantParams.HasParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME)) {
        HILOG_ERROR("no intent name in want");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    executeParam.insightIntentName = wantParams.GetStringParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME);
    if (executeParam.insightIntentName.empty()) {
        HILOG_ERROR("empty intent name");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    executeParam.insightIntentParam = wantParams.GetWantParams(INSIGHT_INTENT_EXECUTE_PARAM_PARAM);
    // The host want may carry the target triple passed through by postCardAction: fields
    // already provided keep the user values; only missing ones are backfilled from
    // FormRecord (AMS requires all three to be non-empty in the end).
    ElementName element = want.GetElement();
    if (element.GetBundleName().empty()) {
        element.SetBundleName(record.bundleName);
    }
    if (element.GetModuleName().empty()) {
        element.SetModuleName(record.moduleName);
    }
    if (element.GetAbilityName().empty()) {
        const std::string mainElement = GetProviderMainElement(record);
        if (mainElement.empty()) {
            HILOG_ERROR("empty mainElement, bundleName:%{public}s, moduleName:%{public}s",
                record.bundleName.c_str(), record.moduleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
        element.SetAbilityName(mainElement);
    }
    want.SetElement(element);
    return ERR_OK;
}

// Put form identity params into the want with system reserved keys, same as RouterEvent
// (int/string branches prevent JS precision overflow).
void SetFormIdentityParams(Want &want, const int64_t formId)
{
    if (formId < MAX_NUMBER_OF_JS) {
        want.SetParam(Constants::PARAM_FORM_ID, formId);
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, formId);
    } else {
        want.SetParam(Constants::PARAM_FORM_ID, std::to_string(formId));
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId));
    }
}
} // namespace

FormEventAdapter::FormEventAdapter()
{
    HILOG_DEBUG("FormEventAdapter created");
}

FormEventAdapter::~FormEventAdapter()
{
}

int FormEventAdapter::MessageEvent(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("invalid formId or null callerToken formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!want.HasParameter(Constants::PARAM_MESSAGE_KEY)) {
        HILOG_ERROR("messageInfo not exist formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form: %{public}" PRId64, matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord formHostRecord;
    bool isHostExist = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, formHostRecord);
    if (!isHostExist) {
        HILOG_ERROR("cannot find target client formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!formHostRecord.Contains(matchedFormId)) {
        HILOG_ERROR("form not self-owned formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    auto errCode = FormProviderMgr::GetInstance().MessageEvent(matchedFormId, record, want);
    if (errCode != ERR_OK) {
        return errCode;
    }
    HILOG_INFO("find target client formId: %{public}" PRId64, formId);

    int32_t callerUserId = FormCommonAdapter::GetInstance().GetCallingUserId();
    NotifyFormClickEvent(formId, FORM_CLICK_MESSAGE, callerUserId);
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    if (!FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
            record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_CLICKED);
        DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, callerUserId);
    }
#endif
    return ERR_OK;
}

int FormEventAdapter::RouterEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId or bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (formId < MAX_NUMBER_OF_JS) {
        want.SetParam(Constants::PARAM_FORM_ID, formId);
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, formId);
    } else {
        want.SetParam(Constants::PARAM_FORM_ID, std::to_string(formId));
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId));
    }

    want.SetParam(Constants::PARAM_APP_CLONE_INDEX_KEY, 0);

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form: %{public}" PRId64, matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    {
        if (!FormBmsHelper::GetInstance().IsBundleMgrValid()) {
            HILOG_ERROR("get bundleMgr failed");
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
    }

    if (record.bundleName != want.GetBundle() && want.GetUriString().empty()) {
        if (!record.isSystemApp) {
            HILOG_WARN("Only system apps can launch the ability of the other apps");
            want.SetBundle(record.bundleName);
        }
    }
    if (FormRouterProxyMgr::GetInstance().HasRouterProxy(formId)) {
        HILOG_INFO("Router proxy was setted sucessful");
        FormRouterProxyMgr::GetInstance().OnFormRouterEvent(formId, want);
        return ERR_OK;
    }
    ApplicationInfo appInfo;
    int32_t result;
    int32_t callerUserId = FormCommonAdapter::GetInstance().GetCallingUserId();
    if (FormBmsHelper::GetInstance().GetApplicationInfo(record.bundleName, callerUserId, appInfo) != ERR_OK) {
        HILOG_ERROR("Get app info failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    SetFreeInstallFlag(record, want);

    if (want.HasParameter(Constants::PARAM_OPEN_TYPE)) {
        int32_t openType = want.GetIntParam(Constants::PARAM_OPEN_TYPE, -1);
        HILOG_INFO("Router by OpenType:%{public}d", openType);
        int32_t openResult = ERR_OK;
        bool isOpened = OpenByOpenType(openType, record, callerToken, want, openResult);
        if (isOpened) {
            return openResult;
        }
    }

    // Log the full want (routing target and passed-through params) before entering AMS for
    // troubleshooting; the want may carry form business data, so log it entirely as private.
    HILOG_INFO("RouterEvent send to ams, want: %{private}s", want.ToString().c_str());

    if (!want.GetUriString().empty()) {
        HILOG_INFO("Router by uri");
        int32_t result = FormAmsHelper::GetInstance().StartAbilityOnlyUIAbility(want, callerToken,
            appInfo.accessTokenId, callerUserId);
        if (result != ERR_OK && result != START_ABILITY_WAITING) {
            HILOG_ERROR("fail StartAbility, result:%{public}d", result);
            return result;
        }
        NotifyFormClickEvent(formId, FORM_CLICK_ROUTER, callerUserId);
        return ERR_OK;
    }
    result = FormAmsHelper::GetInstance().StartAbilityOnlyUIAbility(want, callerToken, appInfo.accessTokenId,
        callerUserId);
    if (result != ERR_OK && result != START_ABILITY_WAITING) {
        HILOG_ERROR("fail StartAbility, result:%{public}d", result);
        return result;
    }

    NotifyFormClickEvent(formId, FORM_CLICK_ROUTER, callerUserId);
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    if (!FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
            record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_CLICKED);
        DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, callerUserId);
    }
#endif
    return ERR_OK;
}

int FormEventAdapter::BackgroundEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId or bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    {
        if (!FormBmsHelper::GetInstance().IsBundleMgrValid()) {
            HILOG_ERROR("get bundleMgr failed");
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
    }

    if (want.GetBundle().empty() || record.bundleName != want.GetBundle()) {
        HILOG_DEBUG("The parameter contains the wrong bundleName or the empty bundleName");
        want.SetBundle(record.bundleName);
    }
    if (!CheckKeepBackgroundRunningPermission(record.bundleName)) {
        HILOG_ERROR("The app does not have permission for keeping background running");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    std::string params = want.GetStringParam(Constants::FORM_CALL_EVENT_PARAMS);
    nlohmann::json jsonObject = SafeJsonParse(params, false);
    if (jsonObject.is_discarded()) {
        HILOG_ERROR("fail parse jsonDataString, length:%{public}zu", params.size());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (!jsonObject.contains(Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY) ||
        !jsonObject.at(Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY).is_string()) {
        HILOG_ERROR("fail get method from params");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<IAbilityConnection> formBackgroundConnection = new (std::nothrow) FormBackgroundConnection(
        formId, want.GetBundle(), want.GetElement().GetAbilityName(),
        jsonObject[Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY].get<std::string>(), params, record.providerUserId);
    if (formBackgroundConnection == nullptr) {
        HILOG_ERROR("null formBackgroundConnection");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    want.SetParam(Constants::PARAM_FORM_ID, formId);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, formId);
    bool isManuallyClick = want.GetBoolParam(Constants::PARAM_FORM_MANUAL_CLICK_KEY, false);
    HILOG_INFO("StartAbilityByCall, MANUAL_CLICK:%{public}d", isManuallyClick);
    int32_t result = FormAmsHelper::GetInstance().StartAbilityByCall(want,
        formBackgroundConnection, callerToken, record.providerUserId, true, isManuallyClick);
    if (result != ERR_OK) {
        HILOG_ERROR("fail StartAbilityByCall, result:%{public}d", result);
        return result;
    }
    NotifyFormClickEvent(formId, FORM_CLICK_CALL, FormCommonAdapter::GetInstance().GetCallingUserId());
    return ERR_OK;
}

int FormEventAdapter::InsightIntentEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    const int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    // insightIntent is only open to preset system app form providers, not system-signed apps.
    if (!record.isSystemApp) {
        HILOG_ERROR("insightIntent rejected, provider is not system app, "
            "bundleName:%{public}s", record.bundleName.c_str());
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
    const uint32_t providerSpecifyTokenId = GetProviderSpecifyTokenId(record.bundleName, record.providerUserId);
    if (providerSpecifyTokenId == 0) {
        HILOG_ERROR("get provider specifyTokenId failed, bundleName:%{public}s", record.bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    InsightIntentExecuteLiteParam executeParam;
    int32_t result = PrepareInsightIntentParam(want, record, executeParam);
    if (result != ERR_OK) {
        return result;
    }
    executeParam.key = static_cast<uint64_t>(matchedFormId);
    executeParam.insightIntentHostClient =
        new (std::nothrow) AbilityRuntime::InsightIntentHostClient();
    if (executeParam.insightIntentHostClient == nullptr) {
        HILOG_ERROR("null insightIntentHostClient");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    // matchedFormId serves as the intent execute callback key; formId goes into want
    // via the system reserved key (same as router).
    SetFormIdentityParams(want, matchedFormId);
    result = FormAmsHelper::GetInstance().ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(
        want, callerToken, executeParam, providerSpecifyTokenId);
    if (result != ERR_OK) {
        HILOG_ERROR("fail ExecuteUIAbilityForegroundIntentWithSpecifyTokenId, result:%{public}d", result);
        return result;
    }
    NotifyFormClickEvent(formId, FORM_CLICK_INSIGHT_INTENT, FormCommonAdapter::GetInstance().GetCallingUserId());
    return ERR_OK;
}

void FormEventAdapter::SetFreeInstallFlag(const FormRecord &record, Want &want)
{
    unsigned int flag = want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND;
    if (!flag) {
        return;
    }
    if (record.isSystemApp) {
        HILOG_INFO("System app want has FLAG_INSTALL_ON_DEMAND");
        want.SetParam(PARAM_FREE_INSTALL_CALLING_UID, record.uid);
    } else {
        HILOG_WARN("Only system app can set FLAG_INSTALL_ON_DEMAND");
        want.RemoveFlags(Want::FLAG_INSTALL_ON_DEMAND);
    }
}

bool FormEventAdapter::OpenByOpenType(const int32_t openType, const FormRecord &record,
    const sptr<IRemoteObject> &callerToken, Want &want, int32_t &openResult)
{
    if (!record.isSystemApp) {
        HILOG_ERROR("Only system app can use openType");
        openResult = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
        return true;
    }

    if (openType == static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_APP_LINKING)) {
        std::string bundleName;
        auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
        if (ret != ERR_OK) {
            HILOG_ERROR("OpenByOpenType get caller bundleName failed");
            openResult = ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
            return true;
        }
        want.SetParam(Want::PARAM_RESV_CALLER_BUNDLE_NAME, bundleName);
        int32_t result = FormAmsHelper::GetInstance().OpenLink(want, callerToken);
        if (result != ERR_OK && result != START_ABILITY_WAITING) {
            HILOG_ERROR("failed OpenLink, result:%{public}d", result);
            openResult = result;
            return true;
        }
        openResult = ERR_OK;
        NotifyFormClickEvent(record.formId, FORM_CLICK_ROUTER, FormCommonAdapter::GetInstance().GetCallingUserId());
        return true;
    }
    if (openType == static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_ATOMIC_SERVICE)) {
        want.SetUri("");
        StartOptions startOptions;
        int32_t result = FormAmsHelper::GetInstance().OpenAtomicService(want, startOptions, callerToken);
        if (result != ERR_OK && result != START_ABILITY_WAITING) {
            HILOG_ERROR("failed OpenAtomicService, result:%{public}d", result);
            openResult = result;
            return true;
        }
        openResult = ERR_OK;
        NotifyFormClickEvent(record.formId, FORM_CLICK_ROUTER, FormCommonAdapter::GetInstance().GetCallingUserId());
        return true;
    }
    if (openType == static_cast<int32_t>(Constants::CardActionParamOpenType::START_ABILITY)) {
        HILOG_INFO("Router by startAbility or uri");
        return false;
    }
    HILOG_ERROR("invalid OpenType:%{public}d", openType);
    return false;
}

void FormEventAdapter::NotifyFormClickEvent(int64_t formId, const std::string &formClickType,
    const int32_t userId)
{
    HILOG_DEBUG("call");

    RunningFormInfo runningFormInfo;
    auto ref = FormDataMgr::GetInstance().GetRunningFormInfosByFormId(formId, runningFormInfo, userId);
    if (ref != ERR_OK) {
        HILOG_ERROR("Get Running info error");
        return;
    }

    FormObserverRecord::GetInstance().HandleFormEvent(runningFormInfo.hostBundleName, formClickType, runningFormInfo);
    // The application layer can pass in an empty Bundlename,
    // Which represents listening to a certain event of all applications
    FormObserverRecord::GetInstance().HandleFormEvent(EMPTY_BUNDLE, formClickType, runningFormInfo);
}

bool FormEventAdapter::CheckKeepBackgroundRunningPermission(const std::string &bundleName)
{
    BundleInfo bundleInfo;
    if (FormBmsHelper::GetInstance().GetBundleInfoWithPermission(bundleName,
        FormCommonAdapter::GetInstance().GetCallingUserId(), bundleInfo)) {
        HILOG_DEBUG("get bundleInfo success");
        auto item = std::find(bundleInfo.reqPermissions.begin(), bundleInfo.reqPermissions.end(),
            Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);
        if (item == bundleInfo.reqPermissions.end()) {
            return false;
        }
    } else {
        HILOG_WARN("can't get bundleInfo's uid");
        return false;
    }

    return true;
}

} // namespace AppExecFwk
} // namespace OHOS