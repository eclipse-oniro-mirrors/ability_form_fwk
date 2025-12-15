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

#include <algorithm>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_storage.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "json_serializer.h"
#include "permission_verification.h"
#include "form_event_report.h"
#include "common_event.h"
#include "common_event_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FMS_IS_READY_EVENT = "fmsIsReady";
const std::string PERMISSION_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
} // namespace
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
    HILOG_INFO("UpdateStaticFormInfos: %{public}s.", bundleName.c_str());
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

ErrCode FormInfoMgr::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        HILOG_ERROR("CheckBundlePermission is failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &bundleFormInfo : bundleFormInfoMap_) {
        if (bundleFormInfo.second != nullptr) {
            bundleFormInfo.second->GetAllTemplateFormsInfo(formInfos, userId);
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

ErrCode FormInfoMgr::GetTemplateFormsInfoByBundle(
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
        bundleFormInfoIter->second->GetAllTemplateFormsInfo(formInfos, userId);
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

ErrCode FormInfoMgr::GetTemplateFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
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
 
    return GetTemplateFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
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

ErrCode FormInfoMgr::GetTemplateFormsInfoByModuleWithoutCheck(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId)
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
        bundleFormInfoIter->second->GetTemplateFormsInfoByModule(moduleName, formInfos, userId);
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
        Constants::FORM_VERSION_CODE != FormUtil::ConvertStringToInt(versionCode);
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

bool FormInfoMgr::IsTemplateFormImperativeFwkValid(const FormInfo &formInfo)
{
    for (const auto &dataIter : formInfo.customizeDatas) {
        if (dataIter.name == Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NAME) {
            auto it = std::find(Constants::TEMPLATE_FORM_IMPERATIVE_FWKS,
                Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END, dataIter.value);
            if (it == Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END) {
                return false;
            }
        }
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
