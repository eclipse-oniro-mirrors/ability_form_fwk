/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_APP_LOCK_HELPER_H
#define OHOS_FORM_FWK_FORM_APP_LOCK_HELPER_H

#include <vector>
#include "form_mgr_errors.h"
#include "app_lock_struct_definition.h"
#include "iapp_lock_manager.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormAppLockHelper
 * App_lock_service helpler.
 */
class FormAppLockHelper {
public:
    static FormAppLockHelper& GetInstance();

    ErrCode RegisterSwitchStateListener();

    void OnSwitchStateChanged(const std::vector<AppSecurityPrivacy::AppLock::SwitchState>& switchState);

private:
    FormAppLockHelper();
    void WithCheckSystemAbility(
        const std::function<void(const sptr<AppSecurityPrivacy::AppLock::IAppLockManager> &)> &consumer);
    void ConsumeWithSystemAbility(
        const std::function<void(const sptr<AppSecurityPrivacy::AppLock::IAppLockManager>&)>& consumer,
        const sptr<IRemoteObject>& sa);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_APP_LOCK_HELPER_H
