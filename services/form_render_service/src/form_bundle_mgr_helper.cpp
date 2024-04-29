/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_bundle_mgr_helper.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
FormBundleMgrHelper::FormBundleMgrHelper() {}

FormBundleMgrHelper::~FormBundleMgrHelper()
{
    if (bundleMgr_ != nullptr && bundleMgr_->AsObject() != nullptr && deathRecipient_ != nullptr) {
        bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    }
}

sptr<IBundleMgr> FormBundleMgrHelper::Connect()
{
    HILOG_DEBUG("Called.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgr_ == nullptr) {
        sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            HILOG_ERROR("Failed to get system ability manager.");
            return nullptr;
        }

        sptr<IRemoteObject> remoteObject_ = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (remoteObject_ == nullptr || (bundleMgr_ = iface_cast<IBundleMgr>(remoteObject_)) == nullptr) {
            HILOG_ERROR("Failed to get bundle mgr service remote object.");
            return nullptr;
        }
        std::weak_ptr<FormBundleMgrHelper> weakPtr = shared_from_this();
        auto deathCallback = [weakPtr](const wptr<IRemoteObject>& object) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr == nullptr) {
                HILOG_ERROR("Bundle helper instance is nullptr.");
                return;
            }
            sharedPtr->OnDeath();
        };
        deathRecipient_ = new (std::nothrow) BundleMgrServiceDeathRecipient(deathCallback);
        if (deathRecipient_ == nullptr) {
            HILOG_ERROR("Failed to create death recipient ptr deathRecipient_!");
            return nullptr;
        }
        if (bundleMgr_->AsObject() != nullptr) {
            bundleMgr_->AsObject()->AddDeathRecipient(deathRecipient_);
        }
    }

    return bundleMgr_;
}

void FormBundleMgrHelper::OnDeath()
{
    HILOG_DEBUG("Called.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (bundleMgr_ == nullptr || bundleMgr_->AsObject() == nullptr) {
        HILOG_ERROR("bundleMgr_ is nullptr.");
        return;
    }
    bundleMgr_->AsObject()->RemoveDeathRecipient(deathRecipient_);
    bundleMgr_ = nullptr;
}

ErrCode FormBundleMgrHelper::GetJsonProfile(ProfileType profileType, const std::string &bundleName,
    const std::string &moduleName, std::string &profile, int32_t userId)
{
    HILOG_DEBUG("Called.");
    auto bundleMgr = Connect();
    if (bundleMgr == nullptr) {
        HILOG_ERROR("Failed to connect.");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    return bundleMgr->GetJsonProfile(profileType, bundleName, moduleName, profile, userId);
}

BundleMgrServiceDeathRecipient::BundleMgrServiceDeathRecipient(
    const std::function<void(const wptr<IRemoteObject>& object)>& deathCallback)
    : deathCallback_(deathCallback) {}

void BundleMgrServiceDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    if (deathCallback_ != nullptr) {
        deathCallback_(object);
    }
}

} // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS