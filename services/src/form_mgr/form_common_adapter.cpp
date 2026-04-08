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

#include "form_mgr/form_common_adapter.h"

#include <cinttypes>
#include <regex>

#include "bundle_info.h"
#include "form_ecological_rule_param.h"
#include "form_info.h"
#include "form_major_info.h"
#include "hap_module_info.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"

#include "bms_mgr/form_bms_helper.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "feature/param_update/param_control.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t SYSTEM_UID = 1000;
constexpr int32_t API_11 = 11;
constexpr int DATA_FIELD = 1;
constexpr int32_t FORM_UPDATE_LEVEL_VALUE_MAX_LENGTH = 3;
constexpr const char *POINT_ETS = ".ets";
constexpr const char *FORM_DATA_PROXY_IGNORE_VISIBILITY = "ohos.extension.form_data_proxy_ignore_visibility";
}

FormCommonAdapter::FormCommonAdapter()
    : formDataMgr_(&FormDataMgr::GetInstance()),
      formInfoMgr_(&FormInfoMgr::GetInstance())
{
    HILOG_DEBUG("FormCommonAdapter created");
}

FormCommonAdapter::~FormCommonAdapter()
{
    HILOG_DEBUG("FormCommonAdapter destroyed");
}

ErrCode FormCommonAdapter::GetFormConfigInfo(const Want& want, FormItemInfo &formItemInfo)
{
    HILOG_DEBUG("GetFormConfigInfo called");
    BundleInfo bundleInfo;
    std::string packageName;
    ErrCode errCode = GetBundleInfo(want, bundleInfo, packageName);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get bundle info failed");
        return errCode;
    }

    FormInfo formInfo;
    errCode = GetFormInfo(want, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get target form info failed");
        return errCode;
    }
    if (!formInfo.IsValid()) {
        HILOG_ERROR("invalid formInfo");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    errCode = GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get form item info failed");
        return errCode;
    }
    formItemInfo.SetPackageName(packageName);
    formItemInfo.SetDeviceId(want.GetElement().GetDeviceID());

    if (!formItemInfo.IsValidItem()) {
        HILOG_ERROR("invalid inputParamItemInfo");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    int formLocation = want.GetParams().GetIntParam(Constants::FORM_LOCATION_KEY,
        static_cast<int>(Constants::FormLocation::OTHER));
    if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
            formLocation >= static_cast<int32_t>(Constants::FormLocation::FORM_LOCATION_END)) {
        HILOG_ERROR("formLocation not FormLocation enum,formLocation = %{public}d", formLocation);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    formItemInfo.SetFormLocation((Constants::FormLocation)formLocation);

    int renderingMode = want.GetParams().GetIntParam(Constants::PARAM_FORM_RENDERINGMODE_KEY,
        static_cast<int>(Constants::RenderingMode::FULL_COLOR));
    formItemInfo.SetRenderingMode((Constants::RenderingMode)renderingMode);

    SetFormEnableAndLockState(formInfo, formItemInfo, formLocation);

    return ERR_OK;
}

void FormCommonAdapter::SetFormEnableAndLockState(FormInfo &formInfo, FormItemInfo &formConfigInfo, int formLocation)
{
    bool isFormBundleForbidden =
        FormBundleForbidMgr::GetInstance().IsBundleForbidden(formConfigInfo.GetProviderBundleName());
    formConfigInfo.SetEnableForm(!isFormBundleForbidden);
    // form is always visible on the lock screen
    if (formLocation == static_cast<int>(Constants::FormLocation::SCREEN_LOCK)) {
        formConfigInfo.SetLockForm(false);
    } else {
        SetLockFormStateOfFormItemInfo(formInfo, formConfigInfo);
    }
}

void FormCommonAdapter::SetLockFormStateOfFormItemInfo(FormInfo &formInfo, FormItemInfo &formConfigInfo)
{
    auto formId = formConfigInfo.GetFormId();
    if (formId > 0 && FormExemptLockMgr::GetInstance().IsExemptLock(formId)) {
        // exempt form must belong to a locked application
        formConfigInfo.SetLockForm(true);
        return;
    }

    bool isBundleProtect = FormBundleLockMgr::GetInstance().IsBundleProtect(formConfigInfo.GetProviderBundleName(),
        GetCallingUserId());
    // Use DBCache to set lockForm first
    FormRecord record;
    if (formId > 0 && FormDbCache::GetInstance().GetDBRecord(formId, record) == ERR_OK) {
        if (isBundleProtect != record.lockForm) {
            record.lockForm = isBundleProtect;
            FormDbCache::GetInstance().UpdateDBRecord(formId, record);
        }
        formConfigInfo.SetLockForm(isBundleProtect);
        formConfigInfo.SetProtectForm(isBundleProtect);
    } else {
        bool isMultiAppForm = FormInfoMgr::GetInstance().IsMultiAppForm(formInfo) &&
            formConfigInfo.GetSystemAppFlag();
        formConfigInfo.SetLockForm(isBundleProtect && !isMultiAppForm);
        formConfigInfo.SetProtectForm(isBundleProtect && !isMultiAppForm);
    }
}

ErrCode FormCommonAdapter::GetBundleInfo(const AAFwk::Want &want, BundleInfo &bundleInfo, std::string &packageName)
{
    HILOG_DEBUG("GetBundleInfo called");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (bundleName.empty() || abilityName.empty() || moduleName.empty()) {
        HILOG_ERROR("invalid bundleName or abilityName or moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    int32_t currentUserId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    ErrCode errCode = FormBmsHelper::GetInstance().GetBundleInfoV9(bundleName, currentUserId, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get bundleInfo failed");
        return errCode;
    }

    bool moduleExist = false;
    for (const auto &moduleInfo : bundleInfo.moduleNames) {
        HILOG_DEBUG("bundleInfo.moduleNames, module name:%{public}s", moduleInfo.c_str());
        if (moduleInfo.compare(moduleName) == 0) {
            moduleExist = true;
            break;
        }
    }
    if (!moduleExist) {
        HILOG_ERROR("GetBundleInfo no such module, name:%{public}s", moduleName.c_str());
        return ERR_APPEXECFWK_FORM_NO_SUCH_MODULE;
    }

    packageName = bundleName + moduleName;
    HILOG_DEBUG("GetBundleInfo end");
    return ERR_OK;
}

ErrCode FormCommonAdapter::GetFormInfo(const AAFwk::Want &want, FormInfo &formInfo)
{
    HILOG_DEBUG("GetFormInfo called");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (bundleName.empty() || abilityName.empty() || moduleName.empty()) {
        HILOG_ERROR("invalid bundleName or abilityName or moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormInfo> formInfos {};
    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    ErrCode errCode = formInfoMgr_->GetFormsInfoByModule(bundleName, moduleName,
        formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("GetFormsInfoByModule,get formConfigInfo failed,userId:%{public}d", userId);
        return errCode;
    }

    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    for (const auto &form : formInfos) {
        if (form.abilityName != abilityName) {
            continue;
        }

        if ((formName.empty() && form.defaultFlag) || form.name == formName) {
            formInfo = form;
            formInfo.moduleName = moduleName;
            HILOG_INFO("GetFormInfo end");
            return ERR_OK;
        }
    }

    HILOG_ERROR("fail get form info,abilityName:%{public}s,formName:%{public}s,userId:%{public}d",
        abilityName.c_str(), formName.c_str(), userId);
    return ERR_APPEXECFWK_FORM_NOT_SUPPORTED;
}

ErrCode FormCommonAdapter::GetFormItemInfo(const AAFwk::Want &want, const BundleInfo &bundleInfo,
                                            const FormInfo &formInfo, FormItemInfo &formItemInfo)
{
    HILOG_DEBUG("GetFormItemInfo start");
    int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, formInfo.defaultDimension);
    if (!IsDimensionValid(formInfo, dimensionId)) {
        HILOG_ERROR("Invalid dimension");
        return ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION;
    }

    ErrCode ret = SetHostBundleName(want, formItemInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("SetHostBundleName failed");
        return ret;
    }

    ret = CreateFormItemInfo(bundleInfo, formInfo, formItemInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("CreateFormItemInfo failed");
        return ret;
    }
    formItemInfo.SetSpecificationId(dimensionId);
    formItemInfo.SetTemporaryFlag(want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false));
    HILOG_DEBUG("GetFormItemInfo end");
    return ERR_OK;
}

ErrCode FormCommonAdapter::CreateFormItemInfo(const BundleInfo& bundleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo)
{
    itemInfo.SetProviderBundleName(bundleInfo.name);
    itemInfo.SetVersionCode(bundleInfo.versionCode);
    itemInfo.SetVersionName(bundleInfo.versionName);
    itemInfo.SetCompatibleVersion(bundleInfo.compatibleVersion);
    itemInfo.SetSystemAppFlag(bundleInfo.applicationInfo.isSystemApp);
    itemInfo.SetProviderUid(bundleInfo.applicationInfo.uid);
    itemInfo.SetDescription(formInfo.description);
    itemInfo.SetAbilityName(formInfo.abilityName);
    itemInfo.SetModuleName(formInfo.moduleName); // formInfo.moduleName: bundleMgr do not set
    itemInfo.SetFormName(formInfo.name);
    itemInfo.SetEnableUpdateFlag(formInfo.updateEnabled);
    itemInfo.SetUpdateDuration(formInfo.updateDuration);
    itemInfo.SetScheduledUpdateTime(formInfo.scheduledUpdateTime);
    itemInfo.SetMultiScheduledUpdateTime(formInfo.multiScheduledUpdateTime);
    itemInfo.SetJsComponentName(formInfo.jsComponentName);
    itemInfo.SetFormVisibleNotify(formInfo.formVisibleNotify);
    auto formSrc = formInfo.src;
    if (formSrc.rfind(POINT_ETS) == formSrc.size() - strlen(POINT_ETS)) {
        formSrc.erase(formSrc.end() - strlen(POINT_ETS), formSrc.end());
    }
    itemInfo.SetFormSrc(formSrc);
    itemInfo.SetFormWindow(formInfo.window);
    itemInfo.SetType(formInfo.type);
    itemInfo.SetUiSyntax(formInfo.uiSyntax);
    itemInfo.SetIsDynamic(formInfo.isDynamic);
    itemInfo.SetTransparencyEnabled(formInfo.transparencyEnabled);
    itemInfo.SetPrivacyLevel(formInfo.privacyLevel);
    itemInfo.SetDataProxyFlag(formInfo.dataProxyEnabled);
    itemInfo.SetFormBundleType(formInfo.bundleType);
    itemInfo.SetConditionUpdate(formInfo.conditionUpdate);
    if (!formInfo.customizeDatas.empty()) {
        for (const auto &customizeData: formInfo.customizeDatas) {
            if (customizeData.name == FORM_DATA_PROXY_IGNORE_VISIBILITY) {
                itemInfo.SetDataProxyIgnoreFormVisibility(!strcasecmp(customizeData.value.c_str(), "true"));
                break;
            }
        }
    }
    int32_t userId = GetCallingUserId();
    itemInfo.SetDistributedForm(FormDistributedMgr::GetInstance().IsBundleDistributed(bundleInfo.name, userId));
    itemInfo.SetUiModuleName(FormDistributedMgr::GetInstance().GetUiModuleName(bundleInfo.name, userId));
    SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    itemInfo.SetIsTemplateForm(formInfo.isTemplateForm);
    return ERR_OK;
}

void FormCommonAdapter::SetFormItemInfoParams(const BundleInfo& bundleInfo, const FormInfo& formInfo,
    FormItemInfo& itemInfo)
{
    std::string templateFormImperativeFwk = Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NONE;
    for (const auto &dataIter : formInfo.customizeDatas) {
        if (dataIter.name == Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NAME) {
            auto it = std::find(Constants::TEMPLATE_FORM_IMPERATIVE_FWKS,
                Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END, dataIter.value);
            if (it != Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END) {
                HILOG_INFO("GotTemplateFormImperativeFwk:%{public}s", dataIter.value.c_str());
                templateFormImperativeFwk = dataIter.value;
                break;
            }
        }
    }
    itemInfo.SetTemplateFormImperativeFwk(templateFormImperativeFwk);

    if (!bundleInfo.hapModuleInfos.empty()) {
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
        }
    }

    HILOG_INFO("size:%{public}zu", bundleInfo.applicationInfo.moduleInfos.size());
    for (const auto &item : bundleInfo.applicationInfo.moduleInfos) {
        HILOG_INFO("moduleName:%{public}s, moduleSourceDir:%{public}s",
            item.moduleName.c_str(), item.moduleSourceDir.c_str());
        if (formInfo.moduleName == item.moduleName) {
            itemInfo.AddHapSourceDirs(item.moduleSourceDir);
        }
    }
}

void FormCommonAdapter::SetFormItemModuleInfo(const HapModuleInfo& hapModuleInfo, const FormInfo& formInfo,
    FormItemInfo& itemInfo)
{
    auto hapPath = hapModuleInfo.hapPath;
    auto moduleName = hapModuleInfo.moduleName;
    HILOG_INFO("module [%{public}s] packageName is %{public}s, hap path is %{public}s", moduleName.c_str(),
        hapModuleInfo.packageName.c_str(), hapPath.c_str());
    if (hapPath.find(Constants::ABS_CODE_PATH) != std::string::npos) {
        hapPath = std::regex_replace(hapPath, std::regex(Constants::ABS_CODE_PATH), 
                                        Constants::LOCAL_BUNDLES);
    }
    nlohmann::json moduleInfos = {
        {Constants::MODULE_PKG_NAME_KEY, hapModuleInfo.packageName},
        {Constants::MODULE_HAP_PATH_KEY, hapPath}
    };
    itemInfo.AddModulePkgName(moduleName, moduleInfos.dump());
    itemInfo.AddModuleInfo(moduleName, hapPath);
    for (const auto &abilityInfo : hapModuleInfo.abilityInfos) {
        if (abilityInfo.name == formInfo.abilityName) {
            itemInfo.SetAbilityModuleName(abilityInfo.moduleName);
            if (!abilityInfo.isModuleJson) {
                itemInfo.SetFormSrc("");
            }
        }
    }
}

ErrCode FormCommonAdapter::SetHostBundleName(const AAFwk::Want &want, FormItemInfo &itemInfo)
{
    std::string hostBundleName;
    bool isSaUid = IPCSkeleton::GetCallingUid() == SYSTEM_UID;
    ErrCode ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    if (isSaUid) {
        hostBundleName = want.GetStringParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY);
        HILOG_INFO("sa uid call CreateFormItemInfo, hostBundleName:%{public}s", hostBundleName.c_str());
        ret = ERR_OK;
    } else {
        ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    }
    if (ret != ERR_OK) {
        HILOG_ERROR("fail get form config info");
        return ret;
    }
    itemInfo.SetHostBundleName(hostBundleName);
    return ERR_OK;
}

bool FormCommonAdapter::IsDimensionValid(const FormInfo &formInfo, int dimensionId) const
{
    HILOG_DEBUG("IsDimensionValid called");
    if (formInfo.supportDimensions.empty()) {
        HILOG_ERROR("Js form,no support dimension");
        return false;
    }

    for (size_t i = 0; i < formInfo.supportDimensions.size() && i < Constants::MAX_LAYOUT; i++) {
        if (formInfo.supportDimensions[i] == dimensionId) {
            return true;
        }
    }

    HILOG_ERROR("No matched dimension found for %{public}d", dimensionId);
    return false;
}

ErrCode FormCommonAdapter::GetFormInfoByFormRecord(const FormRecord &record, FormInfo &formInfo)
{
    HILOG_DEBUG("GetFormInfoByFormRecord called");
    if (record.bundleName.empty() || record.abilityName.empty() || record.moduleName.empty()) {
        HILOG_ERROR("invalid bundleName or abilityName or moduleName");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    std::vector<FormInfo> formInfos {};
    int32_t userId = GetCallingUserId();
    ErrCode errCode = formInfoMgr_->GetFormsInfoByModule(record.bundleName, record.moduleName,
        formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("GetFormsInfoByModule,get formConfigInfo failed,userId:%{public}d", userId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    for (const auto &form : formInfos) {
        if (form.abilityName == record.abilityName && form.moduleName == record.moduleName
            && form.name == record.formName) {
            formInfo = form;
            HILOG_INFO("GetFormInfo end");
            return ERR_OK;
        }
    }
    HILOG_ERROR("fail get form info,abilityName:%{public}s,formName:%{public}s,userId:%{public}d",
        record.abilityName.c_str(), record.formName.c_str(), userId);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int32_t FormCommonAdapter::GetCallerType(std::string bundleName)
{
    HILOG_DEBUG("GetCallerType called, bundleName: %{public}s", bundleName.c_str());
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    AppExecFwk::ApplicationInfo callerAppInfo;
    auto flag = AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO;
    int32_t userId = GetCallingUserId();
    bool getCallerResult = IN_PROCESS_CALL(iBundleMgr->GetApplicationInfo(bundleName, flag, userId, callerAppInfo));
    if (!getCallerResult) {
        HILOG_ERROR("Get callerAppInfo failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    switch (callerAppInfo.bundleType) {
        case AppExecFwk::BundleType::ATOMIC_SERVICE:
            return FormErmsCallerInfo::TYPE_ATOM_SERVICE;
        case AppExecFwk::BundleType::APP:
            return FormErmsCallerInfo::TYPE_HARMONY_APP;
        default:
            HILOG_WARN("the caller type is not harmony app or atom service:%{public}d", callerAppInfo.bundleType);
            break;
    }
    return FormErmsCallerInfo::TYPE_INVALID;
}

int32_t FormCommonAdapter::GetCallingUserId()
{
    HILOG_DEBUG("GetCallingUserId called");
    int callingUid = IPCSkeleton::GetCallingUid();
    return FormUtil::GetCallerUserId(callingUid);
}

void FormCommonAdapter::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("call");

    // Clean the formObservers_.
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("null remoteObject");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(formObserversMutex_);
        for (auto it = formObservers_.begin(); it != formObservers_.end();) {
            auto &remoteObjects = it->second;
            for (auto iter = remoteObjects.begin(); iter != remoteObjects.end();) {
                if (*iter == object) {
                    iter = remoteObjects.erase(iter);
                    continue;
                }
                ++iter;
            }
            if (remoteObjects.empty()) {
                it = formObservers_.erase(it);
                continue;
            }
            ++it;
        }
    }
    std::lock_guard<std::mutex> deathLock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(object);
    if (iter != deathRecipients_.end()) {
        auto deathRecipient = iter->second;
        deathRecipients_.erase(iter);
        object->RemoveDeathRecipient(deathRecipient);
    }
}

void FormCommonAdapter::SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
                                         const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    HILOG_DEBUG("call");
    if (callerToken == nullptr || deathRecipient == nullptr) {
        HILOG_ERROR("empty callerToken or deathRecipient");
        return;
    }
    std::lock_guard<std::mutex> lock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(callerToken);
    if (iter == deathRecipients_.end()) {
        deathRecipients_.emplace(callerToken, deathRecipient);
        callerToken->AddDeathRecipient(deathRecipient);
    } else {
        HILOG_DEBUG("The deathRecipient has been added");
    }
}

void FormCommonAdapter::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("ClientDeathRecipient::OnRemoteDied called");
    FormCommonAdapter::GetInstance().CleanResource(remote);
}

ErrCode FormCommonAdapter::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("RegisterAddObserver called, bundleName:%{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> lock(formObserversMutex_);
    auto formObserver = formObservers_.find(bundleName);
    if (formObserver == formObservers_.end()) {
        HILOG_DEBUG("%{public}s start register", bundleName.c_str());
        std::vector<sptr<IRemoteObject>> remoteObjects;
        remoteObjects.emplace_back(callerToken);
        formObservers_.emplace(bundleName, remoteObjects);
    } else {
        auto &remoteObjects = formObserver->second;
        auto itr = std::find(remoteObjects.begin(), remoteObjects.end(), callerToken);
        if (itr != remoteObjects.end()) {
            HILOG_ERROR("callback is already exist");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        HILOG_DEBUG("%{public}s add register.", bundleName.c_str());
        remoteObjects.emplace_back(callerToken);
    }
    SetDeathRecipient(callerToken, new (std::nothrow) FormCommonAdapter::ClientDeathRecipient());
    HILOG_DEBUG("RegisterAddObserver success");
    return ERR_OK;
}

ErrCode FormCommonAdapter::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("RegisterRemoveObserver called, bundleName:%{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> lock(formObserversMutex_);
    auto formObserver = formObservers_.find(bundleName);
    if (formObserver == formObservers_.end()) {
        HILOG_ERROR("bundleName not exist");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    } else {
        auto &remoteObjects = formObserver->second;
        for (auto itr = remoteObjects.begin(); itr != remoteObjects.end();) {
            if (*itr == callerToken) {
                remoteObjects.erase(itr);
                SetDeathRecipient(callerToken, new (std::nothrow) FormCommonAdapter::ClientDeathRecipient());
                HILOG_DEBUG("RegisterRemoveObserver success");
                return ERR_OK;
            }
            ++itr;
        }
    }
    HILOG_ERROR("callback not exist");
    return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
}

sptr<OHOS::AppExecFwk::IAppMgr> FormCommonAdapter::GetAppMgr()
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemMgr == nullptr) {
        HILOG_ERROR("Fail to get system ability manager");
        return nullptr;
    }
    sptr<IRemoteObject> abilityObj = systemMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (abilityObj == nullptr) {
        HILOG_ERROR("Fail to connect app mgr service");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(abilityObj);
}

void FormCommonAdapter::CheckUpdateFormRecord(const int64_t formId, const FormItemInfo &info, FormRecord &record)
{
    HILOG_DEBUG("CheckUpdateFormRecord called");
    bool needUpdate = false;
    if (record.lowMemoryRecycleStatus != LowMemoryRecycleStatus::NON_RECYCLABLE) {
        record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
        needUpdate = true;
    }

    if (record.formLocation != info.GetFormLocation()) {
        HILOG_INFO("formLocation change oldLocation: %{public}d, newLocation: %{public}d, formId: %{public}" PRId64,
            (int)record.formLocation, (int)info.GetFormLocation(), formId);
        record.formLocation = info.GetFormLocation();
        record.isLocationChange = true;
        needUpdate = true;
    }

    if (info.GetDataProxyIgnoreFormVisibility()) {
        needUpdate = true;
        record.isDataProxyIgnoreFormVisible = true;
    }

    if (needUpdate) {
        formDataMgr_->UpdateFormRecord(formId, record);
    }
}

ErrCode FormCommonAdapter::CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
{
    HILOG_DEBUG("CheckFormDueControl called");
    if (ParamControl::GetInstance().IsDueDisableCtrlEmpty()) {
        // due disable ctrl param empty, just return
        return ERR_OK;
    }

    Want want;
    want.SetElementName(formMajorInfo.bundleName, formMajorInfo.abilityName);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, formMajorInfo.moduleName);

    BundleInfo bundleInfo;
    std::string packageName;
    if (GetBundleInfo(want, bundleInfo, packageName) != ERR_OK) {
        HILOG_ERROR("Get bundle info failed");
        return ERR_OK;
    }

    FormRecord formRecord;
    formRecord.bundleName = formMajorInfo.bundleName;
    formRecord.moduleName = formMajorInfo.moduleName;
    formRecord.abilityName = formMajorInfo.abilityName;
    formRecord.formName = formMajorInfo.formName;
    formRecord.specification = formMajorInfo.dimension;
    formRecord.versionCode = bundleInfo.versionCode;

    return isDisablePolicy ?
        ParamControl::GetInstance().IsFormDisable(formRecord) : ParamControl::GetInstance().IsFormRemove(formRecord);
}

ErrCode FormCommonAdapter::HandleFormAddObserver(const int64_t formId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string hostBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    // Checks if there is a observer on the current host.
    return formDataMgr_->HandleFormAddObserver(hostBundleName, formId, GetCallingUserId());
}

ErrCode FormCommonAdapter::AddFormTimer(const FormRecord &formRecord)
{
    if (!formRecord.isEnableUpdate || formRecord.formTempFlag) {
        HILOG_INFO("isEnableUpdate:%{public}d formTempFlag:%{public}d",
            formRecord.isEnableUpdate, formRecord.formTempFlag);
        return ERR_OK;
    }
    HILOG_WARN("start, formId:%{public}" PRId64, formRecord.formId);
    if (formRecord.updateDuration > 0 && !formRecord.isDataProxy) {
        if (!formDataMgr_->HasFormCloudUpdateDuration(formRecord.bundleName)) {
            UpdateFormCloudUpdateDuration(formRecord.bundleName);
        }
        int64_t updateDuration = formRecord.updateDuration;
        if (!GetValidFormUpdateDuration(formRecord.formId, updateDuration)) {
            HILOG_WARN("Get updateDuration failed, uses local configuration");
        }
        int32_t duration = ParamControl::GetInstance().GetDueUpdateDuration(formRecord);
        if (duration == 0) {
            HILOG_WARN("Due disable interval refresh, formId:%{public}" PRId64, formRecord.formId);
            return ERR_OK;
        }
        int64_t dueDuration = static_cast<int64_t>(duration) * static_cast<int64_t>(Constants::TIME_CONVERSION);
        updateDuration = std::max(updateDuration, dueDuration * Constants::TIME_CONVERSION);
        bool ret = FormTimerMgr::GetInstance().AddFormTimer(formRecord.formId,
            updateDuration, formRecord.providerUserId);
        HILOG_WARN("add interval timer result:%{public}d, formId:%{public}" PRId64, ret, formRecord.formId);
        return ret ? ERR_OK : ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    std::vector<std::vector<int>> updateAtTimes = formRecord.updateAtTimes;
    if (updateAtTimes.size() > 0) {
        HILOG_INFO("updateAtTimes size:%{public}zu", updateAtTimes.size());
        bool ret = FormTimerMgr::GetInstance().AddFormTimerForMultiUpdate(formRecord.formId,
            updateAtTimes, formRecord.providerUserId);
        return ret ? ERR_OK : ERR_APPEXECFWK_FORM_COMMON_CODE;
    } else if (formRecord.updateAtHour >= 0 && formRecord.updateAtMin >= 0) {
        bool ret = FormTimerMgr::GetInstance().AddFormTimer(formRecord.formId,
            formRecord.updateAtHour, formRecord.updateAtMin, formRecord.providerUserId);
        HILOG_WARN("add updateAt timer result:%{public}d, formId:%{public}" PRId64, ret, formRecord.formId);
        return ret ? ERR_OK : ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_WARN("no need add form timer, formId:%{public}" PRId64, formRecord.formId);
    return ERR_OK;
}

bool FormCommonAdapter::GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const
{
    HILOG_DEBUG("call");
    FormRecord formRecord;
    if (!formDataMgr_->GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return false;
    }

    ApplicationInfo appInfo;
    if (FormBmsHelper::GetInstance().GetApplicationInfo(formRecord.bundleName, formRecord.providerUserId,
        appInfo) != ERR_OK) {
        HILOG_ERROR("Get app info failed");
        return false;
    }

    if (appInfo.apiTargetVersion < API_11) {
        HILOG_INFO("API version is lower than 11, uses local configuration");
        updateDuration = formRecord.updateDuration;
        return true;
    }

    int duration = formDataMgr_->GetFormCloudUpdateDuration(formRecord.bundleName);
    if (duration == 0) {
        HILOG_INFO("No valid cloud update duration, uses local configuration");
        updateDuration = formRecord.updateDuration;
        return true;
    }
    int64_t cloudsDuration = duration * Constants::TIME_CONVERSION;
    updateDuration = std::max(formRecord.updateDuration, cloudsDuration);
    return true;
}

void FormCommonAdapter::UpdateFormCloudUpdateDuration(const std::string &bundleName)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        formDataMgr_->RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    std::string additionalInfo;
    if (IN_PROCESS_CALL(iBundleMgr->GetAdditionalInfo(bundleName, additionalInfo)) != ERR_OK) {
        HILOG_ERROR("fail get additionalInfo");
        formDataMgr_->RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    if (additionalInfo.empty()) {
        HILOG_INFO("empty AdditionalInfo");
        formDataMgr_->RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    std::regex regex(R"(formUpdateLevel:(\d+))");
    std::smatch searchResult;
    std::string::const_iterator iterStart = additionalInfo.begin();
    std::string::const_iterator iterEnd = additionalInfo.end();
    std::vector<int> durationArray;
    while (std::regex_search(iterStart, iterEnd, searchResult, regex)) {
        iterStart = searchResult[0].second;
        if (searchResult[DATA_FIELD].str().length() > FORM_UPDATE_LEVEL_VALUE_MAX_LENGTH) {
            continue;
        }
        int val = FormUtil::ConvertStringToInt(searchResult[DATA_FIELD].str());
        if (val >= Constants::MIN_CONFIG_DURATION && val <= Constants::MAX_CONFIG_DURATION) {
            durationArray.emplace_back(val);
        }
    }

    if (durationArray.empty()) {
        HILOG_INFO("No valid formUpdateLevel in additionalInfo");
        formDataMgr_->RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    formDataMgr_->UpdateFormCloudUpdateDuration(bundleName, durationArray.back());
}

} // namespace AppExecFwk
} // namespace OHOS
