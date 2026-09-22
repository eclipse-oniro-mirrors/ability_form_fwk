/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "data_center/form_info/form_info_helper.h"

#include <fstream>

#include "bms_mgr/form_bms_helper.h"
#include "bundle_mgr_client.h"
#include "common/util/file_utils.h"
#include "extension_form_profile.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "ffrt.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_mgr_errors.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "data_center/form_data_mgr.h"
#include "json_util_form.h"
#include "res_config.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int DISTRIBUTED_BUNDLE_MODULE_LENGTH = 2;
constexpr const char *FORM_METADATA_NAME = "ohos.extension.form";
constexpr const char *TEMPLATE_FORM_METADATA_NAME = "ohos.extension.templateForm";
// Matches BundleMgrClientImpl::PROFILE_FILE_PREFIX (bundle_mgr_client_impl.cpp:41).
constexpr const char *PROFILE_FILE_PREFIX = "$profile:";
constexpr size_t PROFILE_FILE_PREFIX_LEN = 9;
constexpr uint32_t GET_BUNDLE_INFO_WITH_ALL_EXTENSIONS =
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_EXCLUDE_EXT) |
    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
}  // namespace

bool FormInfoHelper::LoadSharedModuleInfo(const BundleInfo &bundleInfo, HapModuleInfo &shared)
{
    auto hapModuleInfoBegin = bundleInfo.hapModuleInfos.begin();
    auto hapModuleInfoEnd = bundleInfo.hapModuleInfos.end();
    auto entryIt = std::find_if(hapModuleInfoBegin, hapModuleInfoEnd, [](const auto &hapInfo) {
        return (hapInfo.moduleType == ModuleType::ENTRY) && (!hapInfo.formWidgetModule.empty());
    });
    if (entryIt == hapModuleInfoEnd) {
        return false;
    }

    if (bundleInfo.hapModuleInfos.size() < DISTRIBUTED_BUNDLE_MODULE_LENGTH) {
        // Install distributed hap package
        return true;
    }

    auto sharedIt = std::find_if(hapModuleInfoBegin, hapModuleInfoEnd, [entryIt](const auto &hapInfo) {
        return (hapInfo.moduleType == ModuleType::SHARED) && (!hapInfo.formExtensionModule.empty()) &&
            ((entryIt->name == hapInfo.formExtensionModule) && (entryIt->formWidgetModule == hapInfo.name));
    });
    if (sharedIt == hapModuleInfoEnd) {
        return false;
    }
    shared = *sharedIt;
    return true;
}

ErrCode FormInfoHelper::LoadFormConfigInfoByBundleNames(const std::vector<std::string> &bundleNames,
    int32_t userId, std::unordered_map<std::string, std::vector<FormInfo>> &formInfosMap)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (bundleNames.empty()) {
        HILOG_ERROR("invalid bundleNames");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<BundleInfo> bundleInfos;
    ErrCode ret = FormBmsHelper::GetInstance().BatchGetBundleInfo(
        bundleNames, static_cast<int32_t>(GET_BUNDLE_INFO_WITH_ALL_EXTENSIONS), bundleInfos, userId);
    HILOG_INFO("bundleInfos size:%{public}zu, bundleNames size:%{public}zu", bundleInfos.size(), bundleNames.size());
    if (ret != ERR_OK) {
        HILOG_ERROR("batch get bundleInfo failed, erroCode:%{public}d", ret);
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    for (auto &bundleInfo : bundleInfos) {
        if (bundleInfo.hapModuleInfos.empty()) {
            continue;
        }
        bool hasAbilityInfos = false;
        bool isStageBasedModel = false;
        for (const auto &moduleInfo : bundleInfo.hapModuleInfos) {
            if (!moduleInfo.abilityInfos.empty()) {
                hasAbilityInfos = true;
                isStageBasedModel = moduleInfo.abilityInfos[0].isStageBasedModel;
                break;
            }
        }
        std::vector<FormInfo> formInfos;
        if (!hasAbilityInfos) {
            HILOG_WARN("empty abilityInfos, %{public}s", bundleInfo.name.c_str());
            // Check if current bundle contains FA forms.
            LoadAbilityFormConfigInfo(bundleInfo, formInfos);
            // Check if current bundle contains Stage forms.
            LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
        } else if (isStageBasedModel) {
            LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
        } else {
            LoadAbilityFormConfigInfo(bundleInfo, formInfos);
        }
        formInfosMap.emplace(std::move(bundleInfo.name), std::move(formInfos));
    }
    return ERR_OK;
}

std::shared_ptr<Global::Resource::ResourceManager> FormInfoHelper::GetResMgr(
    std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> &resMgrCache,
    const ExtensionAbilityInfo &extensionInfo)
{
    bool isCompressed = !extensionInfo.hapPath.empty();
    std::string resourcePath = isCompressed ? extensionInfo.hapPath : extensionInfo.resourcePath;
    if (resourcePath.empty()) {
        HILOG_ERROR("resource path is empty, bundleName:%{public}s", extensionInfo.bundleName.c_str());
        return nullptr;
    }
    auto it = resMgrCache.find(resourcePath);
    if (it != resMgrCache.end()) {
        return it->second;
    }
    // Per-hapPath ResourceManager shared by extensions of one bundle; deviates from
    // InitResMgr on purpose: no systemres, and PROF|STRING-only parsing.
    std::shared_ptr<Global::Resource::ResourceManager> resMgr(Global::Resource::CreateResourceManager(false));
    if (resMgr == nullptr) {
        HILOG_ERROR("create ResourceManager failed, bundleName:%{public}s", extensionInfo.bundleName.c_str());
        return nullptr;
    }
    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
    if (resConfig == nullptr) {
        HILOG_ERROR("create ResConfig failed, bundleName:%{public}s", extensionInfo.bundleName.c_str());
        return nullptr;
    }
    resMgr->UpdateResConfig(*resConfig);
    if (!resMgr->AddResource(resourcePath.c_str(),
        Global::Resource::SELECT_PROF | Global::Resource::SELECT_STRING)) {
        HILOG_ERROR("AddResource failed, bundleName:%{public}s", extensionInfo.bundleName.c_str());
        return nullptr;
    }
    resMgrCache.emplace(resourcePath, resMgr);
    return resMgr;
}

bool FormInfoHelper::GetProfilesByResMgr(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr,
    const ExtensionAbilityInfo &extensionInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos)
{
    if (resMgr == nullptr || extensionInfo.metadata.empty()) {
        return false;
    }
    bool isCompressed = !extensionInfo.hapPath.empty();
    for (const auto &data : extensionInfo.metadata) {
        if (metadataName.compare(data.name) != 0) {
            continue;
        }
        const std::string &resName = data.resource;
        size_t pos = resName.rfind(PROFILE_FILE_PREFIX);
        if ((pos == std::string::npos) || (pos == resName.length() - PROFILE_FILE_PREFIX_LEN)) {
            HILOG_WARN("invalid profile resource name");
            continue;
        }
        std::string profileName = resName.substr(pos + PROFILE_FILE_PREFIX_LEN);
        std::string profile;
        bool ret = isCompressed ? GetCompressedProfile(resMgr, profileName, profile)
            : GetRawFileProfile(resMgr, profileName, profile);
        if (!ret) {
            continue;
        }
        profileInfos.emplace_back(profile);
    }
    return !profileInfos.empty();
}

bool FormInfoHelper::GetCompressedProfile(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr,
    const std::string &profileName, std::string &profile)
{
    std::unique_ptr<uint8_t[]> fileContentPtr = nullptr;
    size_t len = 0;
    if (resMgr->GetProfileDataByName(profileName.c_str(), len, fileContentPtr)
        != Global::Resource::SUCCESS) {
        HILOG_WARN("GetProfileDataByName failed");
        return false;
    }
    if (fileContentPtr == nullptr || len == 0) {
        HILOG_WARN("invalid profile data");
        return false;
    }
    // Neither resmgr nor BMS bounds the profile size; reject len > 1MB here if needed.
    // Raw bytes pass through: ExtensionFormProfile::TransformTo is the single JSON parser.
    profile.assign(fileContentPtr.get(), fileContentPtr.get() + len);
    return true;
}

bool FormInfoHelper::GetRawFileProfile(const std::shared_ptr<Global::Resource::ResourceManager> &resMgr,
    const std::string &profileName, std::string &profile)
{
    std::string resPath;
    if (resMgr->GetProfileByName(profileName.c_str(), resPath) != Global::Resource::SUCCESS) {
        HILOG_WARN("profile cannot be found");
        return false;
    }
    if (!FileUtils::IsFileExists(resPath)) {
        HILOG_WARN("invalid profile path");
        return false;
    }
    std::ifstream inFile(resPath, std::ios_base::in | std::ios_base::binary);
    if (!inFile.is_open()) {
        HILOG_WARN("open profile file failed");
        return false;
    }
    // Neither resmgr nor BMS bounds the profile size; check file size (reject > 1MB)
    // before reading if needed.
    profile.assign((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    if (profile.empty()) {
        HILOG_WARN("empty profile file");
        return false;
    }
    return true;
}

ErrCode FormInfoHelper::LoadStageFormConfigInfo(
    const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::shared_ptr<BundleMgrClient> client = DelayedSingleton<BundleMgrClient>::GetInstance();
    if (client == nullptr) {
        HILOG_ERROR("fail get BundleMgrClient");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    // Per-bundle ResourceManager cache: extensions sharing one hapPath reuse a single
    // instance instead of re-initializing per SDK GetResConfigFile call.
    std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> resMgrCache;
    for (const auto &moduleInfo : bundleInfo.hapModuleInfos) {
        for (const auto &extensionInfo : moduleInfo.extensionInfos) {
            if (extensionInfo.type != ExtensionAbilityType::FORM) {
                continue;
            }
            LoadFormsForExtension(client, bundleInfo, extensionInfo, userId, formInfos, resMgrCache);
        }
    }

    UpdateFormInfoByAppServicesCapability(bundleInfo, userId, formInfos);

    // Index destruction is pure deallocation; run it on ffrt workers off the reload chain.
    ffrt::submit([cache = std::move(resMgrCache)]() {
        HILOG_DEBUG("retired %{public}zu resource managers", cache.size());
    });
    return ERR_OK;
}

void FormInfoHelper::LoadFormsForExtension(const std::shared_ptr<BundleMgrClient> &client,
    const BundleInfo &bundleInfo, const ExtensionAbilityInfo &extensionInfo, int32_t userId,
    std::vector<FormInfo> &formInfos,
    std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> &resMgrCache)
{
    HapModuleInfo sharedModule;
    bool hasDistributedForm = LoadSharedModuleInfo(bundleInfo, sharedModule);
    SetDistributedBundleStatus(userId, bundleInfo.entryModuleName, sharedModule.moduleName,
        bundleInfo.name, hasDistributedForm);
    std::vector<std::string> profileInfos {};
    std::vector<std::string> templateProfileInfos {};
    ExtraFormInfo extraFormInfo { hasDistributedForm, sharedModule.moduleName, false };
    if  (hasDistributedForm) {
        if (!client->GetProfileFromSharedHap(sharedModule, extensionInfo, profileInfos)) {
            HILOG_WARN("fail get profile info from shared hap");
            return;
        }
        LoadProfileFormInfos(formInfos, bundleInfo, extensionInfo, profileInfos, extraFormInfo);
        return;
    }
    auto resMgr = GetResMgr(resMgrCache, extensionInfo);
    auto metaData = !GetProfilesByResMgr(resMgr, extensionInfo, FORM_METADATA_NAME, profileInfos);
    bool templateMetaData = true;
    if (bundleInfo.applicationInfo.isSystemApp) {
        templateMetaData = !GetProfilesByResMgr(resMgr, extensionInfo,
            TEMPLATE_FORM_METADATA_NAME, templateProfileInfos);
    }
    if (metaData && templateMetaData) {
        HILOG_ERROR("fail get form metadata : %{public}d, %{public}d", metaData, templateMetaData);
        return;
    }
    LoadProfileFormInfos(formInfos, bundleInfo, extensionInfo, profileInfos, extraFormInfo);
    ExtraFormInfo templateExtraFormInfo { hasDistributedForm, sharedModule.moduleName, true };
    LoadProfileFormInfos(formInfos, bundleInfo, extensionInfo, templateProfileInfos, templateExtraFormInfo);
}

void FormInfoHelper::LoadFormInfos(std::vector<FormInfo> &formInfos, const BundleInfo &bundleInfo,
    const ExtensionAbilityInfo &extensionInfo, const std::string &profileInfo,
    const ExtraFormInfo &extraFormInfo)
{
    std::vector<ExtensionFormInfo> extensionFormInfos;
    int32_t privacyLevel = 0;
    ErrCode errCode = ExtensionFormProfile::TransformTo(profileInfo, extensionFormInfos, privacyLevel);
    if (errCode != ERR_OK) {
        HILOG_WARN("fail transform profile to extension form info");
        return;
    }
    for (const auto &extensionFormInfo: extensionFormInfos) {
        FormInfo formInfo(extensionInfo, extensionFormInfo);
        if (extraFormInfo.isDistributedForm) {
            formInfo.package = extensionInfo.bundleName + extraFormInfo.moduleName;
            formInfo.customizeDatas.push_back({ Constants::DISTRIBUTE_FORM_MODULE, extraFormInfo.moduleName });
        }
        formInfo.versionCode = bundleInfo.versionCode;
        formInfo.bundleType = bundleInfo.applicationInfo.bundleType;
        formInfo.privacyLevel = privacyLevel;
        formInfo.isTemplateForm = extraFormInfo.isTemplateForm;
        PrintLoadStageFormConfigInfo(formInfo, extraFormInfo.isDistributedForm);
        formInfos.emplace_back(std::move(formInfo));
    }
}

void FormInfoHelper::PrintLoadStageFormConfigInfo(const FormInfo &formInfo, bool hasDistributedForm)
{
    HILOG_INFO("LoadStageFormConfigInfo, bundleName:%{public}s, name:%{public}s, renderingMode:%{public}d, "
        "moduleName:%{public}s, hasDistributedForm:%{public}d, isStandbySupported:%{public}d, "
        "isStandbyAdapted:%{public}d, isPrivacySensitive:%{public}d",
        formInfo.bundleName.c_str(),
        formInfo.name.c_str(),
        static_cast<int>(formInfo.renderingMode),
        formInfo.moduleName.c_str(),
        hasDistributedForm,
        formInfo.standby.isSupported,
        formInfo.standby.isAdapted,
        formInfo.standby.isPrivacySensitive);
}

void FormInfoHelper::SetDistributedBundleStatus(int32_t userId, const std::string &entryModule,
    const std::string &uiModule, const std::string &bundleInfoName, bool hasDistributedForm)
{
    DistributedModule distributedModule;
    distributedModule.userId = userId;
    distributedModule.entryModule = entryModule;
    distributedModule.uiModule = uiModule;
    FormDistributedMgr::GetInstance().SetBundleDistributedStatus(bundleInfoName, hasDistributedForm, distributedModule);
}

ErrCode FormInfoHelper::LoadAbilityFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos)
{
    const std::string &bundleName = bundleInfo.name;
    for (const auto &moduleInfo: bundleInfo.hapModuleInfos) {
        const std::string &moduleName = moduleInfo.moduleName;
        std::vector<FormInfo> formInfoVec {};
        if (!FormBmsHelper::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfoVec)) {
            continue;
        }
        for (auto &formInfo: formInfoVec) {
            formInfo.versionCode = bundleInfo.versionCode;
            formInfo.bundleType = bundleInfo.applicationInfo.bundleType;
            formInfos.emplace_back(std::move(formInfo));
        }
    }
    return ERR_OK;
}
std::shared_ptr<Global::Resource::ResourceManager> FormInfoHelper::GetResourceManager(const BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("bundleInfoName:%{public}s", bundleInfo.name.c_str());
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (resourceManager == nullptr) {
        HILOG_ERROR("InitResourceManager failed");
        return nullptr;
    }
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
        if (!moduleResPath.empty()) {
            HILOG_DEBUG("DistributedBms::InitResourceManager, moduleResPath: %{private}s", moduleResPath.c_str());
            if (!resourceManager->AddResource(moduleResPath.c_str())) {
                HILOG_ERROR("DistributedBms::InitResourceManager AddResource failed");
            }
        }
    }
    return resourceManager;
}

ErrCode FormInfoHelper::GetFormInfoDisplayName(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
    FormInfo &formInfo)
{
    if (formInfo.displayNameId != 0 && resourceManager != nullptr) {
        std::string displayName;
        auto state = resourceManager->GetStringById(static_cast<uint32_t>(formInfo.displayNameId), displayName);
        if (state != OHOS::Global::Resource::RState::SUCCESS) {
            HILOG_ERROR("ResourceManager GetStringById with displayNameId failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        formInfo.displayName = displayName;
    }
    return ERR_OK;
}

ErrCode FormInfoHelper::GetFormInfoDescription(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
    FormInfo &formInfo)
{
    if (formInfo.descriptionId != 0 && resourceManager != nullptr) {
        std::string description;
        auto state = resourceManager->GetStringById(static_cast<uint32_t>(formInfo.descriptionId), description);
        if (state != OHOS::Global::Resource::RState::SUCCESS) {
            HILOG_ERROR("ResourceManager GetStringById failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        formInfo.description = description;
    }
    return ERR_OK;
}

void FormInfoHelper::UpdateFormInfoByAppServicesCapability(const BundleInfo &bundleInfo, int32_t userId,
    std::vector<FormInfo> &formInfos)
{
    bool isTransparencyEnabled = false;
    bool isStandbyEnabled = false;
    const std::string &transparencyCapabilityKey = FormDataMgr::GetInstance().GetTransparencyFormCapabilityKey();
    const std::string &standbyCapabilityKey = FormDataMgr::GetInstance().GetFormStandbyCapabilityKey();
    bool needTransparency = !bundleInfo.applicationInfo.isSystemApp && !transparencyCapabilityKey.empty();
    bool needStandby = !standbyCapabilityKey.empty();
    if (needTransparency || needStandby) {
        // One provision fetch shared by both capability checks; previously each consumer
        // fetched independently (two IPCs per non-system bundle).
        CheckAppServicesCapabilities(userId, bundleInfo.applicationInfo.bundleName,
            needTransparency ? transparencyCapabilityKey : "",
            needStandby ? standbyCapabilityKey : "",
            isTransparencyEnabled, isStandbyEnabled);
    }
    UpdateFormInfoTransparencyEnabled(bundleInfo, formInfos, isTransparencyEnabled);
    UpdateFormInfoFormStandby(bundleInfo, formInfos, isStandbyEnabled);
}

void FormInfoHelper::UpdateFormInfoTransparencyEnabled(const BundleInfo &bundleInfo,
    std::vector<FormInfo> &formInfos, bool isTransparencyEnabled)
{
    if (bundleInfo.applicationInfo.isSystemApp) {
        return;
    }
    if (isTransparencyEnabled) {
        return;
    }
    for (auto &formInfo: formInfos) {
        formInfo.transparencyEnabled = false;
    }
}

void FormInfoHelper::UpdateFormInfoFormStandby(const BundleInfo &bundleInfo,
    std::vector<FormInfo> &formInfos, bool isStandbyEnabled)
{
    if (isStandbyEnabled) {
        return;
    }
    for (auto &formInfo: formInfos) {
        formInfo.standby.isSupported = false;
        formInfo.standby.isAdapted = false;
    }
}

bool FormInfoHelper::CheckAppServicesCapabilities(int32_t userId, const std::string &bundleName,
    const std::string &transparencyCapabilityKey, const std::string &standbyCapabilityKey,
    bool &isTransparencyEnabled, bool &isStandbyEnabled)
{
    isTransparencyEnabled = false;
    isStandbyEnabled = false;
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = FormBmsHelper::GetInstance().GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("get AppProvisionInfo failed");
        return false;
    }
    nlohmann::json jsonObject = SafeJsonParse(appProvisionInfo.appServiceCapabilities);
    if (jsonObject.is_discarded() || !jsonObject.is_object()) {
        HILOG_ERROR("fail parse appServiceCapabilities");
        return false;
    }
    if (!transparencyCapabilityKey.empty()) {
        isTransparencyEnabled = jsonObject.contains(transparencyCapabilityKey);
    }
    if (!standbyCapabilityKey.empty()) {
        isStandbyEnabled = jsonObject.contains(standbyCapabilityKey);
    }
    return true;
}

void FormInfoHelper::LoadProfileFormInfos(std::vector<FormInfo> &formInfos, const BundleInfo &bundleInfo,
    const ExtensionAbilityInfo &extensionInfo, const std::vector<std::string> &profileInfos,
    const ExtraFormInfo &extraFormInfo)
{
    for (const auto &profileInfo: profileInfos) {
        LoadFormInfos(formInfos, bundleInfo, extensionInfo, profileInfo, extraFormInfo);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS