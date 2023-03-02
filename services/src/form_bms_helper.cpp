/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "form_bms_helper.h"

#include "ability_manager_interface.h"
#include "erms_mgr_interface.h"
#include "erms_mgr_param.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

sptr<IBundleMgr> FormBmsHelper::GetBundleMgr()
{
    HILOG_INFO("%{public}s called.", __func__);

    if (iBundleMgr_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObject == nullptr) {
            HILOG_ERROR("%{public}s error, failed to get bundle manager service.", __func__);
            return nullptr;
        }

        iBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
        if (iBundleMgr_ == nullptr) {
            HILOG_ERROR("%{public}s error, failed to get bundle manager service", __func__);
            return nullptr;
        }
    }
    return iBundleMgr_;
}

void FormBmsHelper::SetBundleManager(const sptr<IBundleMgr> &bundleManager)
{
    HILOG_DEBUG("SetBundleManager called.");
    iBundleMgr_ = bundleManager;
}

sptr<IEcologicalRuleManager> FormBmsHelper::GetEcologicalRuleMgr()
{
    HILOG_INFO("GetEcologicalRuleMgr called.");

    if (iErMgr_ != nullptr) {
        HILOG_DEBUG("ecological rule mgr already get.");
        return iErMgr_;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        HILOG_ERROR("fail to get systemAbilityManager.");
        return nullptr;
    }
    auto remoteObject = systemAbilityManager->GetSystemAbility(ECOLOGICAL_RULE_SA_ID);
    if (remoteObject == nullptr) {
        HILOG_ERROR("failed to get ecological rule manager service.");
        return nullptr;
    }

    iErMgr_ = iface_cast<IEcologicalRuleManager>(remoteObject);
    if (iErMgr_ == nullptr) {
        HILOG_ERROR("failed to cast ecological rule manager service.");
        return nullptr;
    }
    return iErMgr_;
}

void FormBmsHelper::SetEcologicalRuleMgr(const sptr<IEcologicalRuleManager> &ecologicalRuleManager)
{
    HILOG_INFO("SetEcologicalRuleMgr called.");
    iErMgr_ = ecologicalRuleManager;
}

/**
 * @brief Notify module removable.
 * @param bundleName Provider ability bundleName.
 * @param moduleName Provider ability moduleName.
 */
void FormBmsHelper::NotifyModuleRemovable(const std::string &bundleName, const std::string &moduleName)
{
    HILOG_INFO("%{public}s, bundleName:%{public}s, moduleName:%{public}s",
        __func__, bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        return;
    }

    std::string key = GenerateModuleKey(bundleName, moduleName);
    HILOG_INFO("%{public}s, begin to notify %{public}s removable", __func__, key.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s, failed to get IBundleMgr.", __func__);
        return;
    }

    std::string originId = IPCSkeleton::ResetCallingIdentity();

    IPCSkeleton::SetCallingIdentity(originId);
}
/**
 * @brief Notify module not removable.
 * @param bundleName Provider ability bundleName.
 * @param moduleName Provider ability moduleName.
 */
void FormBmsHelper::NotifyModuleNotRemovable(const std::string &bundleName, const std::string &moduleName)
{
    HILOG_INFO("%{public}s, bundleName:%{public}s, moduleName:%{public}s",
        __func__, bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        return;
    }
    std::string key = GenerateModuleKey(bundleName, moduleName);
    HILOG_INFO("%{public}s, begin to notify %{public}s not removable", __func__, key.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s, failed to get IBundleMgr.", __func__);
        return;
    }

    if (!IN_PROCESS_CALL(iBundleMgr->SetModuleRemovable(bundleName, moduleName, false))) {
        HILOG_ERROR("%{public}s, set not removable failed.", __func__);
        return;
    }
    return;
}

std::string FormBmsHelper::GenerateModuleKey(const std::string &bundleName, const std::string &moduleName) const
{
    return bundleName + "#" + moduleName;
}

bool FormBmsHelper::GetBundlePackInfo(const std::string &bundleName, const int32_t userId,
    BundlePackInfo &bundlePackInfo)
{
    HILOG_INFO("%{public}s, bundleName:%{public}s", __func__, bundleName.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s, failed to get IBundleMgr.", __func__);
        return false;
    }

    if (IN_PROCESS_CALL(iBundleMgr->GetBundlePackInfo(bundleName, GET_PACK_INFO_ALL, bundlePackInfo, userId))
        != ERR_OK) {
        HILOG_ERROR("%{public}s error, failed to get bundle pack info.", __func__);
        return false;
    }

    HILOG_INFO("%{public}s, get bundle pack info success", __func__);
    return true;
}

bool FormBmsHelper::GetAbilityInfo(const AAFwk::Want &want, int32_t userId, AbilityInfo &abilityInfo,
    ExtensionAbilityInfo &extensionInfo)
{
    HILOG_DEBUG("GetAbilityInfo called.");
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    if (bundleName.empty() || abilityName.empty()) {
        HILOG_ERROR("invalid want in explicit query ability info");
        return false;
    }

    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("iBundleMgr is nullptr");
        return false;
    }
    IN_PROCESS_CALL(iBundleMgr->QueryAbilityInfo(want, AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT,
        userId, abilityInfo));
    if (abilityInfo.name.empty() || abilityInfo.bundleName.empty()) {
        HILOG_INFO("get ability info empty, try to get extension info.");
        std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
        IN_PROCESS_CALL(iBundleMgr->QueryExtensionAbilityInfos(want, AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT,
            userId, extensionInfos));
        if (extensionInfos.empty()) {
            HILOG_ERROR("get extension info failed.");
            return false;
        }
        extensionInfo = extensionInfos.front();
        if (extensionInfo.bundleName.empty() || extensionInfo.name.empty()) {
            HILOG_ERROR("get extension info empty.");
            return false;
        }
    }
    return true;
}

bool FormBmsHelper::GetAbilityInfoByAction(const std::string &action, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    if (action.empty()) {
        HILOG_ERROR("input parasm error.");
        return false;
    }

    Want wantAction;
    wantAction.SetAction(action);
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("iBundleMgr is nullptr");
        return false;
    }

    return (IN_PROCESS_CALL(iBundleMgr->ImplicitQueryInfoByPriority(wantAction,
        AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT, userId, abilityInfo, extensionAbilityInfo)));
}

bool FormBmsHelper::GetBundleInfo(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("iBundleMgr is nullptr");
        return false;
    }

    int32_t flags = BundleFlag::GET_BUNDLE_WITH_ABILITIES;
    return (IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId)));
}

bool FormBmsHelper::GetBundleInfoWithPermission(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("iBundleMgr is nullptr");
        return false;
    }

    int32_t flags = BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION;
    return (IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId)));
}

int32_t FormBmsHelper::GetCallerBundleName(std::string &callerBundleName)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s, failed to get IBundleMgr.", __func__);
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleNameForUid(callingUid, callerBundleName))) {
        HILOG_ERROR("%{public}s, failed to get form config info.", __func__);
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    return ERR_OK;
}

int32_t FormBmsHelper::GetUidByBundleName(const std::string &bundleName, const int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("%{public}s, failed to get IBundleMgr.", __func__);
        return INVALID_UID;
    }
    return IN_PROCESS_CALL(iBundleMgr->GetUidByBundleName(bundleName, userId));
}

bool FormBmsHelper::GetCompileMode(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, int32_t &compileMode)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("iBundleMgr is nullptr");
        return false;
    }
    int32_t flags = BundleFlag::GET_BUNDLE_DEFAULT;
    BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId))) {
        HILOG_ERROR("Get bundle info failed.");
        return false;
    }

    for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (!moduleName.empty() && hapModuleInfo.moduleName != moduleName) {
            continue;
        }
        compileMode = static_cast<int32_t>(hapModuleInfo.compileMode);
        return true;
    }

    HILOG_ERROR("Get compile mode failed.");
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS
