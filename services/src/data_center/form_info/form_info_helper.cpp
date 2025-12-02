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

#include "bms_mgr/form_bms_helper.h"
#include "bundle_mgr_client.h"
#include "extension_form_profile.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_mgr_errors.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "data_center/form_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int DISTRIBUTED_BUNDLE_MODULE_LENGTH = 2;
const std::string FORM_METADATA_NAME = "ohos.extension.form";
const std::string DISTRIBUTE_FORM_MODULE = "widgetUiModule";
}

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

ErrCode FormInfoHelper::LoadFormConfigInfoByBundleName(const std::string &bundleName, std::vector<FormInfo> &formInfos,
    int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    BundleInfo bundleInfo;
    int32_t flag = GET_BUNDLE_WITH_EXTENSION_INFO | GET_BUNDLE_WITH_ABILITIES;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flag, bundleInfo, userId))) {
        HILOG_ERROR("get bundleInfo failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    if (bundleInfo.abilityInfos.empty()) {
        HILOG_WARN("empty abilityInfos");
        // Check if current bundle contains FA forms.
        LoadAbilityFormConfigInfo(bundleInfo, formInfos);
        // Check if current bundle contains Stage forms.
        LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
        return ERR_OK;
    }
    if (bundleInfo.abilityInfos[0].isStageBasedModel) {
        LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
    } else {
        LoadAbilityFormConfigInfo(bundleInfo, formInfos);
    }
    return ERR_OK;
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
    for (auto const &extensionInfo: bundleInfo.extensionInfos) {
        if (extensionInfo.type != ExtensionAbilityType::FORM) {
            continue;
        }
        HapModuleInfo sharedModule;
        bool hasDistributedForm = LoadSharedModuleInfo(bundleInfo, sharedModule);
        SetDistributedBundleStatus(userId, bundleInfo.entryModuleName, sharedModule.moduleName,
            bundleInfo.name, hasDistributedForm);
        std::vector<std::string> profileInfos {};
        if  (hasDistributedForm) {
            if (!client->GetProfileFromSharedHap(sharedModule, extensionInfo, profileInfos)) {
                HILOG_WARN("fail get profile info from shared hap");
                continue;
            }
        } else if (!client->GetResConfigFile(extensionInfo, FORM_METADATA_NAME, profileInfos)) {
            HILOG_ERROR("fail get form metadata");
            continue;
        }
        for (const auto &profileInfo: profileInfos) {
            DistributedFormInfo distributedFormInfo { hasDistributedForm, sharedModule.moduleName };
            LoadFormInfos(formInfos, bundleInfo, extensionInfo, profileInfo, distributedFormInfo);
        }
    }

    if (!bundleInfo.applicationInfo.isSystemApp) {
        UpdateBundleTransparencyEnabled(bundleInfo.name, userId, formInfos);
    }

    return ERR_OK;
}

void FormInfoHelper::LoadFormInfos(std::vector<FormInfo> &formInfos, const BundleInfo &bundleInfo,
    const ExtensionAbilityInfo &extensionInfo, const std::string &profileInfo,
    const DistributedFormInfo &distributedFormInfo)
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
        if (distributedFormInfo.isDistributedForm) {
            formInfo.package = extensionInfo.bundleName + distributedFormInfo.moduleName;
            formInfo.customizeDatas.push_back({ DISTRIBUTE_FORM_MODULE, distributedFormInfo.moduleName });
        }
        formInfo.versionCode = bundleInfo.versionCode;
        formInfo.bundleType = bundleInfo.applicationInfo.bundleType;
        formInfo.privacyLevel = privacyLevel;
        PrintLoadStageFormConfigInfo(formInfo, distributedFormInfo.isDistributedForm);
        SendLoadStageFormConfigEvent(formInfo);
        formInfos.emplace_back(formInfo);
    }
}

void FormInfoHelper::PrintLoadStageFormConfigInfo(const FormInfo &formInfo, bool hasDistributedForm)
{
    HILOG_INFO("LoadStageFormConfigInfo, bundleName:%{public}s, name:%{public}s, renderingMode:%{public}d, "
        "moduleName:%{public}s, hasDistributedForm:%{public}d",
        formInfo.bundleName.c_str(), formInfo.name.c_str(), static_cast<int>(formInfo.renderingMode),
        formInfo.moduleName.c_str(), hasDistributedForm);
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

void FormInfoHelper::SendLoadStageFormConfigEvent(const FormInfo &formInfo)
{
    NewFormEventInfo eventInfo;
    eventInfo.bundleName = formInfo.bundleName;
    eventInfo.formName = formInfo.name;
    eventInfo.renderingMode = static_cast<int32_t>(formInfo.renderingMode);
    FormEventReport::SendLoadStageFormConfigInfoEvent(FormEventName::LOAD_STAGE_FORM_CONFIG_INFO,
        HiSysEventType::BEHAVIOR, eventInfo);
}

ErrCode FormInfoHelper::LoadAbilityFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    const std::string &bundleName = bundleInfo.name;
    for (const auto &moduleInfo: bundleInfo.hapModuleInfos) {
        const std::string &moduleName = moduleInfo.moduleName;
        std::vector<FormInfo> formInfoVec {};
        if (!IN_PROCESS_CALL(iBundleMgr->GetFormsInfoByModule(bundleName, moduleName, formInfoVec))) {
            continue;
        }
        for (auto &formInfo: formInfoVec) {
            formInfo.versionCode = bundleInfo.versionCode;
            formInfo.bundleType = bundleInfo.applicationInfo.bundleType;
            formInfos.emplace_back(formInfo);
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

void FormInfoHelper::UpdateBundleTransparencyEnabled(const std::string &bundleName, int32_t userId,
    std::vector<FormInfo> &formInfos)
{
    bool isAGCTransparencyEnabled = GetBundleTransparencyEnabled(bundleName, userId);
    for (auto &formInfo: formInfos) {
        // Only when configured as true will the AGC audit results be set.
        if (formInfo.transparencyEnabled) {
            formInfo.transparencyEnabled = isAGCTransparencyEnabled;
        }
    }
}

bool FormInfoHelper::GetBundleTransparencyEnabled(const std::string &bundleName, int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return false;
    }
    const std::string &transparencyFormCapbilityKey = FormDataMgr::GetInstance().GetTransparencyFormCapbilityKey();
    if (transparencyFormCapbilityKey.empty()) {
        HILOG_ERROR("get transparencyFormCapbilityKey is empty");
        return false;
    }
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = IN_PROCESS_CALL(iBundleMgr->GetAppProvisionInfo(bundleName, userId,
        appProvisionInfo));
    if (ret != ERR_OK) {
        HILOG_ERROR("get AppProvisionInfo failed");
        return false;
    } else {
        nlohmann::json jsonObject = nlohmann::json::parse(appProvisionInfo.appServiceCapabilities,
            nullptr, false);
        if (jsonObject.is_discarded()) {
            HILOG_ERROR("fail parse appServiceCapabilities");
            return false;
        }
        if (!jsonObject.is_object()) {
            HILOG_ERROR("appServiceCapabilities is not object");
            return false;
        }
        return jsonObject.contains(transparencyFormCapbilityKey);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS