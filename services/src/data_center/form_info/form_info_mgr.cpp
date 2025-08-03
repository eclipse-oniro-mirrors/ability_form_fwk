/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "data_center/form_info/form_info_mgr.h"

#include "bundle_mgr_client.h"
#include "extension_form_profile.h"
#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_storage.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "json_serializer.h"
#include "permission_verification.h"
#include "common/event/form_event_report.h"
#include "common_event.h"
#include "common_event_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_METADATA_NAME = "ohos.extension.form";
const std::uint32_t ERR_VERSION_CODE = 0;
const std::string FMS_IS_READY_EVENT = "fmsIsReady";
const std::string PERMISSION_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
} // namespace

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
        LoadStageFormConfigInfo(bundleInfo, formInfos);
        return ERR_OK;
    }
    if (bundleInfo.abilityInfos[0].isStageBasedModel) {
        LoadStageFormConfigInfo(bundleInfo, formInfos);
    } else {
        LoadAbilityFormConfigInfo(bundleInfo, formInfos);
    }
    return ERR_OK;
}

ErrCode FormInfoHelper::LoadStageFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos)
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
            std::vector<ExtensionFormInfo> extensionFormInfos;
            int32_t privacyLevel = 0;
            ErrCode errCode = ExtensionFormProfile::TransformTo(profileInfo, extensionFormInfos, privacyLevel);
            if (errCode != ERR_OK) {
                HILOG_WARN("fail transform profile to extension form info");
                continue;
            }
            for (const auto &extensionFormInfo: extensionFormInfos) {
                FormInfo formInfo(extensionInfo, extensionFormInfo);
                if (!bundleInfo.applicationInfo.isSystemApp) {
                    formInfo.transparencyEnabled = false;
                }
                if (hasDistributedForm) {
                    formInfo.package = extensionInfo.bundleName + sharedModule.moduleName;
                    formInfo.moduleName = sharedModule.moduleName;
                }
                formInfo.versionCode = bundleInfo.versionCode;
                formInfo.bundleType = bundleInfo.applicationInfo.bundleType;
                formInfo.privacyLevel = privacyLevel;
                HILOG_INFO("LoadStageFormConfigInfo, bundleName:%{public}s, name:%{public}s, renderingMode:%{public}d, "
                    "moduleName:%{public}s, hasDistributedForm:%{public}d",
                    formInfo.bundleName.c_str(), formInfo.name.c_str(), static_cast<int>(formInfo.renderingMode),
                    formInfo.moduleName.c_str(), hasDistributedForm);
                NewFormEventInfo eventInfo;
                eventInfo.bundleName = formInfo.bundleName;
                eventInfo.formName = formInfo.name;
                eventInfo.renderingMode = static_cast<int32_t>(formInfo.renderingMode);
                FormEventReport::SendLoadStageFormConfigInfoEvent(FormEventName::LOAD_STAGE_FORM_CONFIG_INFO,
                    HiSysEventType::BEHAVIOR, eventInfo);
                formInfos.emplace_back(formInfo);
            }
        }
    }
    return ERR_OK;
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
    for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
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
    if (formInfo.displayNameId != 0) {
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
    if (formInfo.descriptionId != 0) {
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

BundleFormInfo::BundleFormInfo(const std::string &bundleName) : bundleName_(bundleName)
{
}

ErrCode BundleFormInfo::InitFromJson(const std::string &formInfoStoragesJson)
{
    nlohmann::json jsonObject = nlohmann::json::parse(formInfoStoragesJson, nullptr, false);
    if (jsonObject.is_discarded() || !jsonObject.is_array()) {
        HILOG_ERROR("bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    auto formInfoStorages = jsonObject.get<std::vector<AAFwk::FormInfoStorage>>();
    for (const auto &item : formInfoStorages) {
        formInfoStorages_.push_back(item);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::UpdateStaticFormInfos(int32_t userId)
{
    HILOG_DEBUG("Update static form infos, userId is %{public}d", userId);
    std::vector<FormInfo> formInfos;
    ErrCode errCode = FormInfoHelper::LoadFormConfigInfoByBundleName(bundleName_, formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormConfigInfoByBundleName failed, errCode:%{public}d", errCode);
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    if (!formInfos.empty()) {
        std::vector<FormDBInfo> formDBInfos;
        std::vector<FormInfo> finalFormInfos;
        FormDbCache::GetInstance().GetAllFormDBInfoByBundleName(bundleName_, userId, formDBInfos);
        HandleFormInfosMaxLimit(formInfos, finalFormInfos, formDBInfos);
        bool findUser = false;
        for (auto item = formInfoStorages_.begin(); item != formInfoStorages_.end(); ++item) {
            // Update all user's formInfos
            HILOG_DEBUG("Update formInfos, user:%{public}d", item->userId);
            item->formInfos = finalFormInfos;
            findUser = findUser || (item->userId == userId);
        }
        if (!findUser) {
            HILOG_DEBUG("Add new userId, user:%{public}d", userId);
            formInfoStorages_.emplace_back(userId, finalFormInfos);
        }
    } else {
        HILOG_DEBUG("The new package of %{public}s does not contain a card, clear it", bundleName_.c_str());
        formInfoStorages_.clear();
    }

    return UpdateFormInfoStorageLocked();
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

ErrCode BundleFormInfo::Remove(int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto item = formInfoStorages_.begin(); item != formInfoStorages_.end();) {
        if (item->userId == userId) {
            item = formInfoStorages_.erase(item);
        } else {
            ++item;
        }
    }
    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::AddDynamicFormInfo(const FormInfo &formInfo, int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        bool isSame = false;
        for (const auto &item : formInfoStorage.formInfos) {
            if (item.name == formInfo.name && item.moduleName == formInfo.moduleName) {
                isSame = true;
                break;
            }
        }

        if (isSame) {
            HILOG_ERROR("The same form already exists");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        formInfoStorage.formInfos.push_back(formInfo);
        return UpdateFormInfoStorageLocked();
    }
    // no match user id
    std::vector<FormInfo> formInfos;
    formInfos.push_back(formInfo);
    formInfoStorages_.emplace_back(userId, formInfos);
    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::RemoveDynamicFormInfo(const std::string &moduleName, const std::string &formName,
                                              int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        for (auto item = formInfoStorage.formInfos.begin(); item != formInfoStorage.formInfos.end();) {
            if (item->name != formName || item->moduleName != moduleName) {
                ++item;
                continue;
            }
            // form found
            if (item->isStatic) {
                HILOG_ERROR("the specifiedFormInfo is static,can't be removed");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            item = formInfoStorage.formInfos.erase(item);
            return UpdateFormInfoStorageLocked();
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode BundleFormInfo::RemoveAllDynamicFormsInfo(int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    int32_t numRemoved = 0;
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        for (auto item = formInfoStorage.formInfos.begin(); item != formInfoStorage.formInfos.end();) {
            if (!item->isStatic) {
                ++numRemoved;
                item = formInfoStorage.formInfos.erase(item);
            } else {
                ++item;
            }
        }
        break;
    }
    if (numRemoved > 0) {
        HILOG_ERROR("%{public}d dynamic forms info removed.", numRemoved);
        return UpdateFormInfoStorageLocked();
    }
    return ERR_OK;
}

bool BundleFormInfo::Empty() const
{
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    return formInfoStorages_.empty();
}

ErrCode BundleFormInfo::GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    HILOG_DEBUG("begin");
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetAllFormsInfo(userId, formInfos);
    }
    return ERR_OK;
}

uint32_t BundleFormInfo::GetVersionCode(int32_t userId)
{
    HILOG_DEBUG("begin");
    std::vector<FormInfo> formInfos;
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetAllFormsInfo(userId, formInfos);
        for (const auto &info : formInfos) {
            if (info.versionCode != ERR_VERSION_CODE) {
                return info.versionCode;
            }
        }
    }
    return ERR_VERSION_CODE;
}

ErrCode BundleFormInfo::GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos,
    int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetFormsInfoByModule(userId, moduleName, formInfos);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::GetFormsInfoByFilter(
    const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId)
{
    HILOG_DEBUG("begin");
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    auto newUserId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;

    for (const auto &item : formInfoStorages_) {
        item.GetFormsInfoByFilter(newUserId, filter, formInfos);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::UpdateFormInfoStorageLocked()
{
    ErrCode errCode;
    if (formInfoStorages_.empty()) {
        errCode = FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName_);
    } else {
        nlohmann::json jsonObject = formInfoStorages_;
        if (jsonObject.is_discarded()) {
            HILOG_ERROR("bad form infos");
            return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
        }
        std::string formInfoStoragesStr = jsonObject.dump(Constants::DUMP_INDENT);
        errCode = FormInfoRdbStorageMgr::GetInstance().UpdateBundleFormInfos(bundleName_, formInfoStoragesStr);
    }
    return errCode;
}

void BundleFormInfo::HandleFormInfosMaxLimit(std::vector<FormInfo> &inFormInfos,
    std::vector<FormInfo> &outFormInfos, const std::vector<FormDBInfo> &formDBInfos)
{
    HILOG_INFO("formInfo num: %{public}zu,formDBInfo num: %{public}zu", inFormInfos.size(), formDBInfos.size());
    std::set<std::string> formDBNames;
    GetAllUsedFormName(formDBInfos, inFormInfos, formDBNames);
    if (formDBNames.empty() || inFormInfos.size() <= Constants::FORM_INFO_MAX_NUM) {
        if (inFormInfos.size() > Constants::FORM_INFO_MAX_NUM) {
            unsigned int needPopNum = inFormInfos.size() - Constants::FORM_INFO_MAX_NUM;
            for (unsigned int i = 0; i < needPopNum; i++) {
                inFormInfos.pop_back();
            }
        }
        outFormInfos = inFormInfos;
        return;
    }
    int32_t addFormNum = 0;
    unsigned int formNum = formDBNames.size();
    if (formDBNames.size() < Constants::FORM_INFO_MAX_NUM) {
        addFormNum = Constants::FORM_INFO_MAX_NUM - static_cast<int32_t>(formDBNames.size());
        formNum = Constants::FORM_INFO_MAX_NUM;
    }
    for (auto formInfo : inFormInfos) {
        bool isUsed = formDBNames.find(formInfo.name) != formDBNames.end();
        if (isUsed) {
            outFormInfos.push_back(formInfo);
        } else if (!isUsed && addFormNum > 0) {
            outFormInfos.push_back(formInfo);
            addFormNum--;
        }
        if (outFormInfos.size() == formNum) {
            break;
        }
    }
}

void BundleFormInfo::GetAllUsedFormName(const std::vector<FormDBInfo> &formDBInfos,
    const std::vector<FormInfo> &formInfos, std::set<std::string> &formDBNames)
{
    if (formDBInfos.empty() || formInfos.empty()) {
        return;
    }
    for (auto formDBInfo : formDBInfos) {
        if (formDBNames.count(formDBInfo.formName) > 0) {
            continue;
        }
        for (auto formInfo : formInfos) {
            if (formInfo.name == formDBInfo.formName) {
                formDBNames.insert(formDBInfo.formName);
                break;
            }
        }
    }
    HILOG_INFO("used form num: %{public}zu", formDBNames.size());
}

FormInfoMgr::FormInfoMgr()
{
    HILOG_INFO("create");
}

FormInfoMgr::~FormInfoMgr() = default;

ErrCode FormInfoMgr::Start()
{
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    ErrCode errCode = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormInfos failed");
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &item: formInfoStorages) {
        const std::string &bundleName = item.first;
        const std::string &formInfoStoragesJson = item.second;
        auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
        errCode = bundleFormInfoPtr->InitFromJson(formInfoStoragesJson);
        if (errCode != ERR_OK) {
            continue;
        }
        HILOG_INFO("load bundle %{public}s form infos success.", bundleName.c_str());
        bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    }
    HILOG_INFO("load bundle form infos from db done");
    return ERR_OK;
}

ErrCode FormInfoMgr::UpdateStaticFormInfos(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::shared_ptr<BundleFormInfo> bundleFormInfoPtr;
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto search = bundleFormInfoMap_.find(bundleName);
    if (search != bundleFormInfoMap_.end()) {
        bundleFormInfoPtr = search->second;
    } else {
        bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
    }

    ErrCode errCode = bundleFormInfoPtr->UpdateStaticFormInfos(userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("UpdateStaticFormInfos failed!");
        return errCode;
    }

    if (bundleFormInfoPtr->Empty()) {
        // no forms found, no need to be inserted into the map
        return ERR_OK;
    }

    bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    HILOG_INFO("success, bundleName=%{public}s", bundleName.c_str());
    return ERR_OK;
}

ErrCode FormInfoMgr::Remove(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        // BundleFormInfo not found, no need to remove
        return ERR_OK;
    }

    ErrCode errCode = ERR_OK;
    if (bundleFormInfoIter->second != nullptr) {
        errCode = bundleFormInfoIter->second->Remove(userId);
    }

    if (bundleFormInfoIter->second && bundleFormInfoIter->second->Empty()) {
        bundleFormInfoMap_.erase(bundleFormInfoIter);
    }
    HILOG_INFO("success, bundleName=%{public}s", bundleName.c_str());
    return errCode;
}

ErrCode FormInfoMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        HILOG_ERROR("CheckBundlePermission is failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &bundleFormInfo : bundleFormInfoMap_) {
        if (bundleFormInfo.second != nullptr) {
            bundleFormInfo.second->GetAllFormsInfo(formInfos, userId);
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByFilter(
    const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        if (filter.bundleName.empty() || !IsCaller(filter.bundleName)) {
            HILOG_ERROR("Permission is wrong");
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
        }
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    if (filter.bundleName.empty()) {
        for (const auto &bundleFormInfo : bundleFormInfoMap_) {
            if (bundleFormInfo.second != nullptr) {
                bundleFormInfo.second->GetFormsInfoByFilter(filter, formInfos, userId);
            }
        }
    } else {
        auto bundleFormInfoIter = bundleFormInfoMap_.find(filter.bundleName);
        if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
            HILOG_WARN("no forms found for bundle name:%{public}s", filter.bundleName.c_str());
            return ERR_OK;
        }
        if (bundleFormInfoIter->second != nullptr) {
            bundleFormInfoIter->second->GetFormsInfoByFilter(filter, formInfos, userId);
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByBundle(
    const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetAllFormsInfo(formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        HILOG_ERROR("CheckBundlePermission and IsCaller failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    return GetFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
}

ErrCode FormInfoMgr::GetFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found for %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetFormsInfoByModule(moduleName, formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByRecord(const FormRecord &formRecord, FormInfo &formInfo)
{
    std::vector<FormInfo> formInfos;
    {
        std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        auto bundleFormInfoIter = bundleFormInfoMap_.find(formRecord.bundleName);
        if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
            HILOG_ERROR("no forms found for %{public}s", formRecord.bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }

        if (bundleFormInfoIter->second == nullptr) {
            HILOG_ERROR("null BundleFormInfo");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }

        bundleFormInfoIter->second->GetFormsInfoByModule(formRecord.moduleName, formInfos);
    }
    for (const FormInfo &info : formInfos) {
        if (info.name == formRecord.formName) {
            formInfo = info;
            break;
        }
    }
    return formInfo.name.empty() ? ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED : ERR_OK;
}

ErrCode FormInfoMgr::CheckDynamicFormInfo(FormInfo &formInfo, const BundleInfo &bundleInfo)
{
    for (auto &moduleInfo : bundleInfo.hapModuleInfos) {
        if (formInfo.moduleName != moduleInfo.moduleName) {
            continue;
        }
        for (auto &abilityInfo : moduleInfo.abilityInfos) {
            if (formInfo.abilityName != abilityInfo.name) {
                continue;
            }
            formInfo.src = "";
            return ERR_OK;
        }
        for (auto &extensionInfos : moduleInfo.extensionInfos) {
            if (formInfo.abilityName != extensionInfos.name) {
                continue;
            }
            formInfo.src = "./js/" + formInfo.name + "/pages/index/index";
            return ERR_OK;
        }
        HILOG_ERROR("No match abilityName found");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }

    HILOG_ERROR("No match moduleName found");
    return ERR_APPEXECFWK_FORM_NO_SUCH_MODULE;
}

ErrCode FormInfoMgr::AddDynamicFormInfo(FormInfo &formInfo, int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    BundleInfo bundleInfo;
    int32_t flag = GET_BUNDLE_WITH_EXTENSION_INFO | GET_BUNDLE_WITH_ABILITIES;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(formInfo.bundleName, flag, bundleInfo, userId))) {
        HILOG_ERROR("get bundleInfo failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    ErrCode errCode = CheckDynamicFormInfo(formInfo, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail CheckDynamicFormInfo");
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(formInfo.bundleName);
    std::shared_ptr<BundleFormInfo> bundleFormInfoPtr;
    if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
        bundleFormInfoPtr = bundleFormInfoIter->second;
    } else {
        bundleFormInfoPtr = std::make_shared<BundleFormInfo>(formInfo.bundleName);
    }

    return bundleFormInfoPtr->AddDynamicFormInfo(formInfo, userId);
}

ErrCode FormInfoMgr::RemoveDynamicFormInfo(const std::string &bundleName, const std::string &moduleName,
                                           const std::string &formName, int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found in bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return bundleFormInfoIter->second->RemoveDynamicFormInfo(moduleName, formName, userId);
}

ErrCode FormInfoMgr::RemoveAllDynamicFormsInfo(const std::string &bundleName, int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found in bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return bundleFormInfoIter->second->RemoveAllDynamicFormsInfo(userId);
}

std::shared_ptr<BundleFormInfo> FormInfoMgr::GetOrCreateBundleFromInfo(const std::string &bundleName)
{
    {
        std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
        if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
            // found
            return bundleFormInfoIter->second;
        }
    }

    // not found
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    // try to find again
    if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
        // found
        return bundleFormInfoIter->second;
    }
    auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
    bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    return bundleFormInfoPtr;
}

bool FormInfoMgr::IsCaller(const std::string& bundleName)
{
    auto bms = FormBmsHelper::GetInstance().GetBundleMgr();
    if (bms == nullptr) {
        HILOG_ERROR("fail get Bundle Mgr");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = IN_PROCESS_CALL(
        bms->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, FormUtil::GetCurrentAccountId()));
    if (!ret) {
        HILOG_ERROR("get bundleInfo failed");
        return false;
    }
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    if (bundleInfo.applicationInfo.accessTokenId == callerToken) {
        return true;
    }
    return false;
}

bool FormInfoMgr::CheckBundlePermission()
{
    if (FormUtil::IsSACall()) {
        return true;
    }
    if (FormUtil::VerifyCallingPermission(AppExecFwk::Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        return true;
    }
    HILOG_ERROR("Permission verification failed");
    return false;
}

ErrCode FormInfoMgr::ReloadFormInfos(const int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("userId:%{public}d", userId);
    std::map<std::string, std::uint32_t> bundleVersionMap {};
    ErrCode result = GetBundleVersionMap(bundleVersionMap, userId);
    if (result != ERR_OK) {
        return result;
    }
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    hasReloadedFormInfosState_ = false;
    UpdateBundleFormInfos(bundleVersionMap, userId);
    for (auto const &bundleVersionPair : bundleVersionMap) {
        std::shared_ptr<BundleFormInfo> bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleVersionPair.first);
        ErrCode errCode = bundleFormInfoPtr->UpdateStaticFormInfos(userId);
        if (errCode != ERR_OK || bundleFormInfoPtr->Empty()) {
            continue;
        }
        bundleFormInfoMap_[bundleVersionPair.first] = bundleFormInfoPtr;
        HILOG_INFO("add forms info success, bundleName=%{public}s, versionCode:%{public}d",
            bundleVersionPair.first.c_str(), bundleVersionPair.second);
    }
    hasReloadedFormInfosState_ = true;
    bool publishRet = PublishFmsReadyEvent();
    if (!publishRet) {
        HILOG_ERROR("failed to publish fmsIsReady event with permission");
    }
    HILOG_INFO("end, formInfoMapSize:%{public}zu", bundleFormInfoMap_.size());
    return ERR_OK;
}

bool FormInfoMgr::PublishFmsReadyEvent()
{
    HILOG_INFO("publish fmsIsReady event");
    Want eventWant;
    eventWant.SetAction(FMS_IS_READY_EVENT);
    CommonEventData eventData;
    eventData.SetWant(eventWant);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({PERMISSION_REQUIRE_FORM});
    bool ret = EventFwk::CommonEventManager::PublishCommonEvent(eventData, publishInfo);
    return ret;
}

bool FormInfoMgr::HasReloadedFormInfos()
{
    HILOG_DEBUG("Reloaded Form Infos state %{public}d", hasReloadedFormInfosState_);
    return hasReloadedFormInfosState_;
}

ErrCode FormInfoMgr::GetBundleVersionMap(std::map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    std::vector<ExtensionAbilityInfo> extensionInfos {};
    if (!IN_PROCESS_CALL(iBundleMgr->QueryExtensionAbilityInfos(ExtensionAbilityType::FORM, userId, extensionInfos))) {
        HILOG_ERROR("get extension infos failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    std::vector<BundleInfo> bundleInfos {};
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfos(GET_BUNDLE_WITH_ABILITIES, bundleInfos, userId))) {
        HILOG_ERROR("get bundle infos failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    // get names of bundles that must contain stage forms
    for (auto const &extensionInfo : extensionInfos) {
        bundleVersionMap.insert(std::make_pair(extensionInfo.bundleName, extensionInfo.applicationInfo.versionCode));
    }
    // get names of bundles that may contain fa forms
    for (auto const &bundleInfo : bundleInfos) {
        if (!bundleInfo.abilityInfos.empty() && !bundleInfo.abilityInfos[0].isStageBasedModel) {
            bundleVersionMap.insert(std::make_pair(bundleInfo.name, bundleInfo.versionCode));
        }
    }
    return ERR_OK;
}

void FormInfoMgr::UpdateBundleFormInfos(std::map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId)
{
    std::string versionCode;
    FormInfoRdbStorageMgr::GetInstance().GetFormVersionCode(versionCode);
    bool isNeedUpdateAll = versionCode.empty() ||
        Constants::FORM_VERSION_CODE > FormUtil::ConvertStringToInt(versionCode);
    HILOG_INFO("bundle number:%{public}zu, old versionCode:%{public}s, new versionCode:%{public}d",
        bundleVersionMap.size(), versionCode.c_str(), Constants::FORM_VERSION_CODE);
    for (auto const &bundleFormInfoPair : bundleFormInfoMap_) {
        const std::string &bundleName = bundleFormInfoPair.first;
        auto bundleVersionPair = bundleVersionMap.find(bundleName);
        if (bundleVersionPair == bundleVersionMap.end()) {
            bundleFormInfoPair.second->Remove(userId);
            HILOG_INFO("remove forms info success, bundleName=%{public}s", bundleName.c_str());
            continue;
        }
        if (!isNeedUpdateAll) {
            uint32_t newVersionCode = bundleVersionPair->second;
            uint32_t oldVersionCode = bundleFormInfoPair.second->GetVersionCode(userId);
            HILOG_INFO("bundleName=%{public}s, bundle version old:%{public}d, new:%{public}d",
                bundleName.c_str(), oldVersionCode, newVersionCode);
            if (oldVersionCode == newVersionCode) {
                bundleVersionMap.erase(bundleVersionPair);
                continue;
            }
        }
        bundleVersionMap.erase(bundleVersionPair);
        bundleFormInfoPair.second->UpdateStaticFormInfos(userId);
        HILOG_INFO("update forms info success, bundleName=%{public}s", bundleName.c_str());
    }
    if (isNeedUpdateAll) {
        FormInfoRdbStorageMgr::GetInstance().UpdateFormVersionCode();
    }
}

ErrCode FormInfoMgr::GetAppFormVisibleNotifyByBundleName(const std::string &bundleName,
    int32_t providerUserId, bool &appFormVisibleNotify)
{
    std::lock_guard<std::mutex> lock(appFormVisibleNotifyMapMutex_);
    auto iter = appFormVisibleNotifyMap_.find(bundleName);
    if (iter == appFormVisibleNotifyMap_.end()) {
        sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
        if (iBundleMgr == nullptr) {
            HILOG_ERROR("get IBundleMgr failed");
            return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
        }
        AppExecFwk::ApplicationInfo info;
        if (!IN_PROCESS_CALL(iBundleMgr->GetApplicationInfo(bundleName,
            AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, providerUserId, info))) {
            HILOG_ERROR("get ApplicationInfo failed");
            return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
        }
        appFormVisibleNotifyMap_.emplace(bundleName, info.formVisibleNotify);
        appFormVisibleNotify = info.formVisibleNotify;
        HILOG_INFO("bundleName=%{public}s, appFormVisibleNotify=%{public}d", bundleName.c_str(), appFormVisibleNotify);
    } else {
        appFormVisibleNotify = iter->second;
    }
    return ERR_OK;
}

bool FormInfoMgr::IsMultiAppForm(const FormInfo &formInfo)
{
    bool isMultiAppForm = false;
    for (auto dataIter = formInfo.customizeDatas.begin(); dataIter != formInfo.customizeDatas.end();) {
        if (Constants::IS_MULTI_APP_FORM == dataIter->name && Constants::IS_MULTI_APP_FORM_TRUE == dataIter->value) {
            isMultiAppForm = true;
            break;
        }
        ++dataIter;
    }
    return isMultiAppForm;
}
}  // namespace AppExecFwk
}  // namespace OHOS
