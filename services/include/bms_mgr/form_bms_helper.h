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

#ifndef OHOS_FORM_FWK_FORM_BMS_HELPER_H
#define OHOS_FORM_FWK_FORM_BMS_HELPER_H

#include <singleton.h>
#include "ability_manager_interface.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_interface.h"
#include "bms_mgr/form_bundle_event_callback.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

/**
 * @class FormBmsHelper
 * Bms helpler.
 */
class FormBmsHelper final : public DelayedRefSingleton<FormBmsHelper> {
    DECLARE_DELAYED_REF_SINGLETON(FormBmsHelper)

public:
    DISALLOW_COPY_AND_MOVE(FormBmsHelper);

    /**
     * @brief Notify module removable.
     * @param bundleName Provider ability bundleName.
     * @param moduleName Provider ability moduleName.
     */
    void NotifyModuleRemovable(const std::string &bundleName, const std::string &moduleName);
    /**
     * @brief Notify module not removable.
     * @param bundleName Provider ability bundleName.
     * @param moduleName Provider ability moduleName.
     */
    void NotifyModuleNotRemovable(const std::string &bundleName, const std::string &moduleName);

    /**
     * @brief Acquire a bundle manager, if it not existed,
     * @return returns the bundle manager ipc object, or nullptr for failed.
     */
    sptr<IBundleMgr> GetBundleMgr();

    /**
     * @brief Acquire a bundle install manager, if it not existed,
     * @return returns the bundle manager ipc object, or nullptr for failed.
     */
    sptr<IBundleInstaller> GetBundleInstaller();

    /**
     * @brief Add the bundle manager instance for debug.
     * @param bundleManager the bundle manager ipc object.
     */
    void SetBundleManager(const sptr<IBundleMgr> &bundleManager);

    /**
     * @brief Get bundle package info.
     * @param bundleName Indicates the bundle name.
     * @param userId Indicates the user ID.
     * @param bundlePackInfo Indicates the obtained BundlePackInfo object.
     * @return Returns true on success, false on failure.
     */
    bool GetBundlePackInfo(const std::string &bundleName, int32_t userId, BundlePackInfo &bundlePackInfo);

    /**
     * @brief Get ability info
     * @param want The desired action to look for.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @return Returns true on success, false on failure.
     */
    bool GetAbilityInfo(const Want &want, int32_t userId, AbilityInfo &abilityInfo);

    /**
     * @brief Get ability info by action
     * @param action The desired action to look for.
     * @param userId Indicates the user ID.
     * @param abilityInfo Indicates the obtained AbilityInfo object.
     * @param extensionAbilityInfo Indicates the obtained extension.
     * @return Returns true on success, false on failure.
     */
    bool GetAbilityInfoByAction(const std::string &action, int32_t userId, AbilityInfo &abilityInfo,
        ExtensionAbilityInfo &extensionAbilityInfo);

    /**
     * @brief Obtains the BundleInfo with abilities based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param userId Indicates the user ID.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfo(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo);

    /**
     * @brief Obtains the BundleInfo with Permission based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param userId Indicates the user ID.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfoWithPermission(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo);

    /**
     * @brief Obtains the BundleInfo with default info based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param userId Indicates the user ID.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfoDefault(const std::string& bundleName, int32_t userId, BundleInfo &bundleInfo);

    /**
     * @brief Obtains the BundleInfo by flags based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the flags.
     * @param userId Indicates the user ID.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfoByFlags(const std::string& bundleName, int32_t flags, int32_t userId, BundleInfo &bundleInfo);

    /**
     * @brief Obtains the BundleInfo based on a given bundle name.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param userId Indicates the user ID.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @return Returns ERR_OK if the BundleInfo is successfully obtained.
     */
    ErrCode GetBundleInfoV9(const std::string& bundleName, int32_t userId, BundleInfo &bundleInfo);

    /**
     * @brief Get caller bundle name.
     * @param callerBundleName Indicates the caller bundle name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t GetCallerBundleName(std::string &callerBundleName);

    /**
     * @brief Obtains the application UID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the uid if successfully obtained; returns -1 otherwise.
     */
    int32_t GetUidByBundleName(const std::string &bundleName, int32_t userId);

    bool GetCompileMode(const std::string &bundleName, const std::string &moduleName,
        int32_t userId, int32_t &compileMode);

    bool GetCompatibleVersion(const std::string& bundleName, int32_t userId, int32_t& compatibleVersion);

    int32_t GetBundleNameByUid(const int32_t uid, std::string &bundleName);

    ErrCode GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
        int32_t userId, std::vector<ProxyData> &proxyData);

    ErrCode GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyData);

    ErrCode GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo);

    ErrCode RegisterBundleEventCallback();
    ErrCode UnregisterBundleEventCallback();
    static constexpr int64_t INVALID_UID = -1;
private:
    /**
     * @brief Generate module key.
     * @param bundleName Provider ability bundleName.
     * @param moduleName Provider ability moduleName.
     * @return Module key.
     */
    std::string GenerateModuleKey(const std::string &bundleName, const std::string &moduleName) const;

private:
    sptr<IBundleMgr> iBundleMgr_ = nullptr;
    sptr<IBundleInstaller> bundleInstallerProxy_ = nullptr;
    sptr<FormBundleEventCallback> formBundleEventCallback_ = nullptr;
    std::mutex ibundleMutex_;
    std::mutex registerMutex_;
    bool hasRegisterBundleEvent_ = false;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_BMS_HELPER_H
