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

#include "bms_mgr/form_bms_helper.h"

#include "ability_manager_interface.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{
    HILOG_INFO("call");
}

FormBmsHelper::~FormBmsHelper()
{
    HILOG_INFO("call");
}

sptr<IBundleMgr> FormBmsHelper::GetBundleMgr()
{
    HILOG_DEBUG("call");
    if (iBundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(ibundleMutex_);
        if (iBundleMgr_ == nullptr) {
            sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (remoteObject == nullptr) {
                HILOG_ERROR("fail get bundle manager service");
                return nullptr;
            }

            iBundleMgr_ = iface_cast<IBundleMgr>(remoteObject);
            if (iBundleMgr_ == nullptr) {
                HILOG_ERROR("fail get bundle manager service");
                return nullptr;
            }
        }
    }

    return iBundleMgr_;
}

sptr<IBundleInstaller> FormBmsHelper::GetBundleInstaller()
{
    HILOG_DEBUG("call");
    if (bundleInstallerProxy_ == nullptr) {
        sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
        if (iBundleMgr != nullptr) {
            bundleInstallerProxy_ = iBundleMgr->GetBundleInstaller();
        }
    }
    return bundleInstallerProxy_;
}


void FormBmsHelper::SetBundleManager(const sptr<IBundleMgr> &bundleManager)
{
    HILOG_DEBUG("call");
    iBundleMgr_ = bundleManager;
}

/**
 * @brief Notify module removable.
 * @param bundleName Provider ability bundleName.
 * @param moduleName Provider ability moduleName.
 */
void FormBmsHelper::NotifyModuleRemovable(const std::string &bundleName, const std::string &moduleName)
{
    HILOG_DEBUG("notify module removable, bundleName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        return;
    }

    std::string key = GenerateModuleKey(bundleName, moduleName);
    HILOG_DEBUG("begin to notify %{public}s removable", key.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
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
    HILOG_INFO("bundleName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        return;
    }
    std::string key = GenerateModuleKey(bundleName, moduleName);
    HILOG_DEBUG("begin to notify %{public}s not removable", key.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return;
    }

    if (!IN_PROCESS_CALL(iBundleMgr->SetModuleRemovable(bundleName, moduleName, false))) {
        HILOG_ERROR("set not removable failed");
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
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return false;
    }

    if (IN_PROCESS_CALL(iBundleMgr->GetBundlePackInfo(bundleName, GET_PACK_INFO_ALL, bundlePackInfo, userId))
        != ERR_OK) {
        HILOG_ERROR("fail get bundle pack info");
        return false;
    }

    HILOG_DEBUG("get bundle pack info success");
    return true;
}

bool FormBmsHelper::GetAbilityInfo(const AAFwk::Want &want, int32_t userId, AbilityInfo &abilityInfo)
{
    HILOG_DEBUG("call");
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    if (bundleName.empty() || abilityName.empty()) {
        HILOG_ERROR("invalid want in explicit query ability info");
        return false;
    }

    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return false;
    }
    return IN_PROCESS_CALL(
        iBundleMgr->QueryAbilityInfo(want, AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT, userId, abilityInfo));
}

bool FormBmsHelper::GetAbilityInfoByAction(const std::string &action, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo)
{
    HILOG_DEBUG("call");
    if (action.empty()) {
        HILOG_ERROR("input parasm error");
        return false;
    }

    Want wantAction;
    wantAction.SetAction(action);
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return false;
    }

    return (IN_PROCESS_CALL(iBundleMgr->ImplicitQueryInfoByPriority(wantAction,
        AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT, userId, abilityInfo, extensionAbilityInfo)));
}

bool FormBmsHelper::GetBundleInfo(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    return GetBundleInfoByFlags(bundleName, BundleFlag::GET_BUNDLE_WITH_ABILITIES, userId, bundleInfo);
}

bool FormBmsHelper::GetBundleInfoWithPermission(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    return GetBundleInfoByFlags(bundleName, BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION, userId, bundleInfo);
}

bool FormBmsHelper::GetBundleInfoDefault(const std::string& bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    return GetBundleInfoByFlags(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, userId, bundleInfo);
}

bool FormBmsHelper::GetBundleInfoByFlags(const std::string& bundleName, int32_t flags, int32_t userId,
    BundleInfo &bundleInfo)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return false;
    }
    return (IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId)));
}

ErrCode FormBmsHelper::GetBundleInfoV9(const std::string& bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (IN_PROCESS_CALL(iBundleMgr->GetBundleInfoV9(bundleName,
        (static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY) +
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)),
        bundleInfo, userId)) != ERR_OK) {
        HILOG_ERROR("get bundleInfo failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    return ERR_OK;
}

int32_t FormBmsHelper::GetCallerBundleName(std::string &callerBundleName)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    auto callingUid = IPCSkeleton::GetCallingUid();
    if (IN_PROCESS_CALL(iBundleMgr->GetNameForUid(callingUid, callerBundleName)) != ERR_OK) {
        HILOG_ERROR("fail get form config info");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    HILOG_INFO("get form config info end");
    return ERR_OK;
}

int32_t FormBmsHelper::GetBundleNameByUid(const int32_t uid, std::string &bundleName)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (IN_PROCESS_CALL(iBundleMgr->GetNameForUid(uid, bundleName)) != ERR_OK) {
        HILOG_ERROR("fail get bundle name by uid");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    return ERR_OK;
}

int32_t FormBmsHelper::GetUidByBundleName(const std::string &bundleName, const int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return INVALID_UID;
    }
    return IN_PROCESS_CALL(iBundleMgr->GetUidByBundleName(bundleName, userId));
}

bool FormBmsHelper::GetCompileMode(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, int32_t &compileMode)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return false;
    }
    int32_t flags = BundleFlag::GET_BUNDLE_DEFAULT;
    BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId))) {
        HILOG_ERROR("Get bundle info failed");
        return false;
    }

    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (!moduleName.empty() && hapModuleInfo.moduleName != moduleName) {
            continue;
        }
        compileMode = static_cast<int32_t>(hapModuleInfo.compileMode);
        return true;
    }

    HILOG_ERROR("Get compile mode failed");
    return false;
}

bool FormBmsHelper::GetCompatibleVersion(const std::string& bundleName, int32_t userId, int32_t& compatibleVersion)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return false;
    }
    int32_t flags = BundleFlag::GET_BUNDLE_DEFAULT;
    BundleInfo bundleInfo;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId))) {
        HILOG_ERROR("Get bundle info failed");
        return false;
    }

    compatibleVersion = static_cast<int32_t>(bundleInfo.compatibleVersion);
    return true;
}

ErrCode FormBmsHelper::GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, std::vector<ProxyData> &proxyData)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    return IN_PROCESS_CALL(iBundleMgr->GetProxyDataInfos(bundleName, moduleName, proxyData, userId));
}

ErrCode FormBmsHelper::GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyData)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    return IN_PROCESS_CALL(iBundleMgr->GetAllProxyDataInfos(proxyData, userId));
}

ErrCode FormBmsHelper::GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("null iBundleMgr");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    return IN_PROCESS_CALL(iBundleMgr->GetApplicationInfoV9(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
        userId, appInfo));
}

ErrCode FormBmsHelper::RegisterBundleEventCallback()
{
    if (!hasRegisterBundleEvent_) {
        std::lock_guard<std::mutex> lock(registerMutex_);
        if (!hasRegisterBundleEvent_) {
            HILOG_INFO("call");
            sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
            if (iBundleMgr == nullptr) {
                return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
            }
            formBundleEventCallback_ = new (std::nothrow) FormBundleEventCallback();
            if (formBundleEventCallback_ == nullptr) {
                HILOG_ERROR("allocate formBundleEventCallback_ failed");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            if (!iBundleMgr->RegisterBundleEventCallback(formBundleEventCallback_)) {
                HILOG_ERROR("RegisterBundleEventCallback failed");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            hasRegisterBundleEvent_ = true;
        }
    }

    return ERR_OK;
}

ErrCode FormBmsHelper::UnregisterBundleEventCallback()
{
    sptr<IBundleMgr> iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    if (!iBundleMgr->UnregisterBundleEventCallback(formBundleEventCallback_)) {
        HILOG_ERROR("RegisterBundleEventCallback failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    formBundleEventCallback_ = nullptr;
    hasRegisterBundleEvent_ = false;
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
