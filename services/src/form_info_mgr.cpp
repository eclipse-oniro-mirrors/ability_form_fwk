/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_info_mgr.h"

#include "bundle_mgr_client.h"
#include "extension_form_profile.h"
#include "form_bms_helper.h"
#include "form_info_storage.h"
#include "form_info_rdb_storage_mgr.h"
#include "form_mgr_errors.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "json_serializer.h"
#include "permission_verification.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_METADATA_NAME = "ohos.extension.form";
} // namespace

ErrCode FormInfoHelper::LoadFormConfigInfoByBundleName(const std::string &bundleName, std::vector<FormInfo> &formInfos,
    int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is invalid");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("failed to get IBundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfo, userId))) {
        HILOG_ERROR("failed to get bundle info.");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    // Check if current bundle contains FA forms.
    if (LoadAbilityFormConfigInfo(bundleInfo, formInfos) != ERR_OK) {
        HILOG_INFO("No fa form config info found for %{public}s.", bundleName.c_str());
    }
    // Check if current bundle contains Stage forms.
    if (LoadStageFormConfigInfo(bundleInfo, formInfos) != ERR_OK) {
        HILOG_INFO("No stage form config info found for %{public}s.", bundleName.c_str());
    }
    return ERR_OK;
}

ErrCode FormInfoHelper::LoadStageFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos)
{
    std::shared_ptr<BundleMgrClient> client = DelayedSingleton<BundleMgrClient>::GetInstance();
    if (client == nullptr) {
        HILOG_ERROR("failed to get BundleMgrClient.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    std::shared_ptr<OHOS::Global::Resource::ResourceManager> resourceManager = GetResourceManager(bundleInfo);
    if (resourceManager == nullptr) {
        HILOG_ERROR("InitResourceManager failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    for (auto const &extensionInfo: bundleInfo.extensionInfos) {
        if (extensionInfo.type != ExtensionAbilityType::FORM) {
            continue;
        }

        std::vector<std::string> profileInfos {};
        if (!client->GetResConfigFile(extensionInfo, FORM_METADATA_NAME, profileInfos)) {
            HILOG_ERROR("failed to get form metadata.");
            continue;
        }

        for (const auto &profileInfo: profileInfos) {
            std::vector<ExtensionFormInfo> extensionFormInfos;
            ErrCode errCode = ExtensionFormProfile::TransformTo(profileInfo, extensionFormInfos);
            if (errCode != ERR_OK) {
                HILOG_WARN("failed to transform profile to extension form info");
                continue;
            }
            for (const auto &extensionFormInfo: extensionFormInfos) {
                FormInfo formInfo(extensionInfo, extensionFormInfo); 
                if (GetFormInfoDescription(resourceManager, formInfo) != ERR_OK) {
                    HILOG_INFO("Get FormInfo Description fail");
                }
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
        HILOG_ERROR("failed to get IBundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    std::shared_ptr<OHOS::Global::Resource::ResourceManager> resourceManager = GetResourceManager(bundleInfo);
    if (resourceManager == nullptr) {
        HILOG_ERROR("InitResourceManager failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    const std::string &bundleName = bundleInfo.name;
    for (const auto &modelInfo: bundleInfo.hapModuleInfos) {
        const std::string &moduleName = modelInfo.moduleName;
        std::vector<FormInfo> formInfoVec {};
        if (!IN_PROCESS_CALL(iBundleMgr->GetFormsInfoByModule(bundleName, moduleName, formInfoVec))) {
            continue;
        }
        for (auto &formInfo: formInfoVec) {
            if (GetFormInfoDescription(resourceManager, formInfo) != ERR_OK) {
                HILOG_INFO("Get FormInfo Description fail");
            }
            formInfos.emplace_back(formInfo);
        }
    }

    return ERR_OK;
}
std::shared_ptr<Global::Resource::ResourceManager> FormInfoHelper::GetResourceManager(const BundleInfo &bundleInfo)
{
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    if (resourceManager == nullptr) {
        HILOG_ERROR("InitResourceManager failed");
        return nullptr;
    }
    for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath = hapModuleInfo.resourcePath;
        if (!moduleResPath.empty()) {
            HILOG_INFO("DistributedBms::InitResourceManager, moduleResPath: %{private}s", moduleResPath.c_str());
            if (!resourceManager->AddResource(moduleResPath.c_str())) {
                HILOG_ERROR("DistributedBms::InitResourceManager AddResource failed");
            }
        }
    }
    return resourceManager;
}

ErrCode FormInfoHelper::GetFormInfoDescription(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager, FormInfo &formInfo)
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
    if (jsonObject.is_discarded()) {
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
    HILOG_INFO("Update static form infos, userId is %{public}d.", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    std::vector<FormInfo> formInfos;
    ErrCode errCode = FormInfoHelper::LoadFormConfigInfoByBundleName(bundleName_, formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormConfigInfoByBundleName failed, errCode:%{public}d.", errCode);
        return errCode;
    }

    if (!formInfos.empty()) {
        bool findUser = false;
        for (auto item = formInfoStorages_.begin(); item != formInfoStorages_.end(); ++item) {
            // Update all user's formInfos
            HILOG_DEBUG("Update formInfos, user: %{public}d", item->userId);
            item->formInfos = formInfos;
            findUser |= (item->userId == userId);
        }
        if (!findUser) {
            HILOG_DEBUG("Add new userId, user: %{public}d", userId);
            formInfoStorages_.emplace_back(userId, formInfos);
        }
    }

    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::Remove(int32_t userId)
{
    HILOG_INFO("Remove form infos, userId is %{public}d.", userId);
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
    HILOG_INFO("Add dynamic form info, userId is %{public}d.", userId);
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
    HILOG_INFO("remove dynamic form info, userId is %{public}d.", userId);
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
                HILOG_ERROR("The specified form info is static, can not be removed.");
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
    HILOG_INFO("remove all dynamic forms info, userId is %{public}d.", userId);
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

ErrCode BundleFormInfo::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("%{public}s begin.",  __func__);
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    int32_t userId = FormUtil::GetCurrentAccountId();
    for (const auto &item : formInfoStorages_) {
        item.GetAllFormsInfo(userId, formInfos);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    int32_t userId = FormUtil::GetCurrentAccountId();
    for (const auto &item : formInfoStorages_) {
        item.GetFormsInfoByModule(userId, moduleName, formInfos);
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
            HILOG_ERROR("bad form infos.");
            return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
        }
        std::string formInfoStoragesStr = jsonObject.dump(Constants::DUMP_INDENT);
        errCode = FormInfoRdbStorageMgr::GetInstance().UpdateBundleFormInfos(bundleName_, formInfoStoragesStr);
    }
    return errCode;
}

FormInfoMgr::FormInfoMgr()
{
    HILOG_INFO("FormInfoMgr is created");
}

FormInfoMgr::~FormInfoMgr() = default;

ErrCode FormInfoMgr::Start()
{
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    ErrCode errCode = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormInfos failed.");
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
    HILOG_INFO("load bundle form infos from db done.");
    return ERR_OK;
}

ErrCode FormInfoMgr::UpdateStaticFormInfos(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
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
        return errCode;
    }

    if (bundleFormInfoPtr->Empty()) {
        // no forms found, no need to be inserted into the map
        return ERR_OK;
    }

    bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    HILOG_INFO("update forms info success, bundleName=%{public}s.", bundleName.c_str());
    return ERR_OK;
}

ErrCode FormInfoMgr::Remove(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
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
    HILOG_INFO("remove forms info success, bundleName=%{public}s.", bundleName.c_str());
    return errCode;
}

ErrCode FormInfoMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    bool hasPermission = CheckBundlePermission();
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    if (hasPermission) {
        for (const auto &bundleFormInfo : bundleFormInfoMap_) {
            if (bundleFormInfo.second != nullptr) {
                bundleFormInfo.second->GetAllFormsInfo(formInfos);
            }
        }
    } else {
        for (const auto &bundleFormInfo : bundleFormInfoMap_) {
            if (IsCaller(bundleFormInfo.first)) {
                if (bundleFormInfo.second != nullptr) {
                    bundleFormInfo.second->GetAllFormsInfo(formInfos);
                }
                return ERR_OK;
            }
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByBundle(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found.");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetAllFormsInfo(formInfos);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
                                          std::vector<FormInfo> &formInfos)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        HILOG_ERROR("CheckBundlePermission and IsCaller failed.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found for %{public}s.", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetFormsInfoByModule(moduleName, formInfos);
    }
    return ERR_OK;
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
        HILOG_ERROR("failed to get IBundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    BundleInfo bundleInfo;
    int32_t flag = GET_BUNDLE_WITH_EXTENSION_INFO | GET_BUNDLE_WITH_ABILITIES;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(formInfo.bundleName, flag, bundleInfo, userId))) {
        HILOG_ERROR("failed to get bundle info.");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    ErrCode errCode = CheckDynamicFormInfo(formInfo, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("failed to CheckDynamicFormInfo.");
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
        HILOG_ERROR("no forms found in bundle %{public}s.", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return bundleFormInfoIter->second->RemoveDynamicFormInfo(moduleName, formName, userId);
}

ErrCode FormInfoMgr::RemoveAllDynamicFormsInfo(const std::string &bundleName, int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found in bundle %{public}s.", bundleName.c_str());
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
        HILOG_ERROR("Failed to get Bundle Mgr.");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = IN_PROCESS_CALL(
        bms->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, FormUtil::GetCurrentAccountId()));
    if (!ret) {
        HILOG_ERROR("Failed to get bundle info.");
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
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (isSaCall) {
        return true;
    }
    auto isCallingPerm = AAFwk::PermissionVerification::GetInstance()->VerifyCallingPermission(
        AppExecFwk::Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED);
    if (isCallingPerm) {
        return true;
    }
    HILOG_ERROR("Permission verification failed");
    return false;
}

ErrCode FormInfoMgr::ReloadFormInfos(const int32_t userId)
{
    HILOG_INFO("ReloadFormInfos userId: %{public}d.", userId);
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("failed to get IBundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    std::vector<ApplicationInfo> appInfos {};
    if (!IN_PROCESS_CALL(iBundleMgr->GetApplicationInfos(GET_BASIC_APPLICATION_INFO, userId, appInfos))) {
        HILOG_ERROR("failed to get Application info.");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    std::set<std::string> bundleNameSet {};
    for (auto const &appInfo : appInfos) {
        bundleNameSet.emplace(appInfo.bundleName);
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (auto const &bundleFormInfoPair : bundleFormInfoMap_) {
        const std::string &bundleName = bundleFormInfoPair.first;
        auto setFindIter = bundleNameSet.find(bundleName);
        if (setFindIter == bundleNameSet.end()) {
            bundleFormInfoPair.second->Remove(userId);
            HILOG_INFO("remove forms info success, bundleName=%{public}s", bundleName.c_str());
            continue;
        }
        bundleNameSet.erase(setFindIter);
        bundleFormInfoPair.second->UpdateStaticFormInfos(userId);
        HILOG_INFO("update forms info success, bundleName=%{public}s", bundleName.c_str());
    }

    for (auto const &bundleName : bundleNameSet) {
        std::shared_ptr<BundleFormInfo> bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
        ErrCode errCode = bundleFormInfoPtr->UpdateStaticFormInfos(userId);
        if (errCode != ERR_OK || bundleFormInfoPtr->Empty()) {
            continue;
        }
        bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
        HILOG_INFO("add forms info success, bundleName=%{public}s", bundleName.c_str());
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
