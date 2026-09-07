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
#include "insight_intent/insight_intent_execute_param.h"
#include "insight_intent_host_client.h"
#include "running_form_info.h"
#include "start_options.h"
#include "tokenid_kit.h"

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

// 系统签名应用：非预置、但以系统证书签名（profile 中 app-feature 为 hos_system_app）。
// 其 AccessToken 系统应用标志位与预置系统应用一致，可通过 fullTokenId 查询，与是否预装无关。

// 拼接提供方 fullTokenId（高 32 位 tokenAttr + 低 32 位 hapTokenId），查询失败返回 0。
uint64_t GetProviderFullTokenId(const std::string &bundleName, const int32_t userId)
{
    if (bundleName.empty()) {
        return 0;
    }
    const auto tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, 0);
    if (tokenId == 0) {
        HILOG_ERROR("GetHapTokenID failed, userId:%{public}d, bundleName:%{public}s",
            userId, bundleName.c_str());
        return 0;
    }
    Security::AccessToken::HapTokenInfo hapInfo;
    if (Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo)
        != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        HILOG_ERROR("GetHapTokenInfo failed, bundleName:%{public}s", bundleName.c_str());
        return 0;
    }
    constexpr int32_t TOKEN_ID_BIT_SIZE = 32;
    return (static_cast<uint64_t>(hapInfo.tokenAttr) << TOKEN_ID_BIT_SIZE) + tokenId;
}

bool IsSystemSignedProvider(const std::string &bundleName, const int32_t providerUserId)
{
    // tokenAttr 为 fullTokenId 的高 32 位，拼接后查询系统应用标志位。
    const uint64_t fullTokenId = GetProviderFullTokenId(bundleName, providerUserId);
    return fullTokenId != 0 && Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

// 意图执行目标是提供方模块的入口 UIAbility（module.json5 的 mainElement，如 EntryAbility），
// 而非提供卡片的 FormExtensionAbility（record.abilityName）。AMS 侧 GenerateWant 以该
// abilityName 设置 element，并与装饰器/配置条目声明的 abilityName 严格比对，若回填
// FormExtensionAbility 名会导致 "ability name mismatch" 且拉起目标错误。
std::string GetProviderMainElement(const FormRecord &record, const int32_t userId)
{
    BundleInfo bundleInfo;
    const int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE);
    if (!FormBmsHelper::GetInstance().GetBundleInfoByFlags(record.bundleName, flags, userId, bundleInfo)) {
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

    // insightIntent 仅开放给系统应用的卡片提供方：预置系统应用走 FormRecord 标志，
    // 非预置的系统签名应用走 AccessToken 标志位。
    if (!record.isSystemApp && !IsSystemSignedProvider(record.bundleName, record.providerUserId)) {
        HILOG_ERROR("insightIntent rejected, provider is not system app or system signed app, "
            "bundleName:%{public}s", record.bundleName.c_str());
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    // specifyTokenId 需传提供方 fullTokenId（高 32 位 tokenAttr + 低 32 位 hapTokenId）：
    // AMS 侧 JudgeCallerIsAllowedToUseSystemAPIByTokenId 以完整 64 位判定系统应用身份，
    // 32 位 accessTokenId 零扩展后高 32 位为 0，会被判非系统应用（ERR_NOT_SYSTEM_APP）。
    const int32_t callerUserId = FormCommonAdapter::GetInstance().GetCallingUserId();
    const uint64_t providerFullTokenId = GetProviderFullTokenId(record.bundleName, record.providerUserId);
    if (providerFullTokenId == 0) {
        HILOG_ERROR("get provider fullTokenId failed, bundleName:%{public}s", record.bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    InsightIntentExecuteParam executeParam;
    if (!InsightIntentExecuteParam::GenerateFromWant(want, executeParam)) {
        HILOG_ERROR("GenerateFromWant failed, formId:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // Host want carries no element; AMS CheckAndUpdateParam requires
    // bundleName/moduleName/insightIntentName non-empty, fill provider info from form record.
    executeParam.bundleName_ = record.bundleName;
    executeParam.moduleName_ = record.moduleName;
    if (executeParam.abilityName_.empty()) {
        // 卡片侧不传 abilityName；回填提供方模块 mainElement（入口 UIAbility）。
        // record.abilityName 为 FormExtensionAbility 名，不能作为意图执行目标。
        executeParam.abilityName_ = GetProviderMainElement(record, callerUserId);
        if (executeParam.abilityName_.empty()) {
            HILOG_ERROR("empty mainElement, bundleName:%{public}s, moduleName:%{public}s",
                record.bundleName.c_str(), record.moduleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
    }

    sptr<AbilityRuntime::InsightIntentHostClient> insightIntentHostClient =
        new (std::nothrow) AbilityRuntime::InsightIntentHostClient();
    if (insightIntentHostClient == nullptr) {
        HILOG_ERROR("null insightIntentHostClient");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // key = matchedFormId: intent executing client handle, same as native ExecuteIntent.
    // specifyTokenId 传提供方 fullTokenId：AMS 侧以完整 64 位判定系统应用身份，
    // 权限校验取其低 32 位（hapTokenId），callerToken 为宿主 token。
    // formId 透传 matchedFormId（规范化完整卡片 id）：AMS 侧据此向最终 Want 注入
    // 卡片标识参数（ohos.extra.param.key.form_identity / formID），供返回动画锚定
    // 到卡片，与 router 链路（RouterEvent 注入的参数集）对齐。
    const int32_t result = FormAmsHelper::GetInstance().ExecuteIntentWithSpecifyTokenId(
        static_cast<uint64_t>(matchedFormId), insightIntentHostClient, executeParam, want.GetParams(),
        providerFullTokenId, callerToken, matchedFormId);
    if (result != ERR_OK) {
        HILOG_ERROR("fail ExecuteIntentWithSpecifyTokenId, result:%{public}d", result);
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