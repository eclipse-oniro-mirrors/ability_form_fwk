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

#ifndef OHOS_FORM_FWK_FORM_BUNDLE_MGR_HELPER_H
#define OHOS_FORM_FWK_FORM_BUNDLE_MGR_HELPER_H

#include <singleton.h>

#include "bundle_mgr_interface.h"
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {

class FormBundleMgrHelper : public std::enable_shared_from_this<FormBundleMgrHelper> {
public:
    DISALLOW_COPY_AND_MOVE(FormBundleMgrHelper);
    
    ErrCode GetJsonProfile(ProfileType profileType, const std::string &bundleName,
        const std::string &moduleName, std::string &profile, int32_t userId = UNSPECIFIED_USERID);

    static constexpr int UNSPECIFIED_USERID = -2;
private:
    sptr<IBundleMgr> Connect();
    void OnDeath();
	
private:
    DECLARE_DELAYED_SINGLETON(FormBundleMgrHelper)
    std::mutex mutex_;
    sptr<IBundleMgr> bundleMgr_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
};

class BundleMgrServiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit BundleMgrServiceDeathRecipient(
        const std::function<void(const wptr<IRemoteObject>& object)>& deathCallback);
    DISALLOW_COPY_AND_MOVE(BundleMgrServiceDeathRecipient);
    virtual ~BundleMgrServiceDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject>& object) override;

private:
    std::function<void(const wptr<IRemoteObject>& object)> deathCallback_;
};

} // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_BUNDLE_MGR_HELPER_H