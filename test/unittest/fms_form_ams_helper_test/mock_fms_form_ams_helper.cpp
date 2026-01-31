/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ams_mgr/form_ams_helper.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace {
    bool g_mockGetAbilityManagerRet = true;
}

void MockGetAbilityManager(bool mockRet)
{
    g_mockGetAbilityManagerRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormAmsHelper::FormAmsHelper()
{}

FormAmsHelper::~FormAmsHelper()
{}

sptr<AAFwk::IAbilityManager> FormAmsHelper::GetAbilityManager()
{
    if (!g_mockGetAbilityManagerRet) {
        return nullptr;
    }
    if (abilityManager_ == nullptr) {
        sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemManager == nullptr) {
            HILOG_ERROR("get registry failed");
            return nullptr;
        }
        sptr<IRemoteObject> remoteObject = systemManager->GetSystemAbility(ABILITY_MGR_SERVICE_ID);
        if (remoteObject == nullptr) {
            HILOG_ERROR("connect AbilityMgrService failed");
            return nullptr;
        }

        abilityManager_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    }

    return abilityManager_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
