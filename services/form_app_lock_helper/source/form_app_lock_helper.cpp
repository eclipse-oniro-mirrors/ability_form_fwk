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

#include "form_app_lock_helper.h"
#include "iservice_registry.h"

#include "fms_log_wrapper.h"
#include "app_lock_manager_client.h"
#include "form_event_register.h"
#include "form_mgr_errors.h"
#include "form_mgr_adapter.h"

namespace OHOS {
namespace AppExecFwk {

using namespace AppSecurityPrivacy::AppLock;

FormAppLockHelper::FormAppLockHelper()
{}

FormAppLockHelper &FormAppLockHelper::GetInstance()
{
    static FormAppLockHelper instance;
    return instance;
}

ErrCode FormAppLockHelper::RegisterSwitchStateListener()
{
    HILOG_INFO("RegisterSwitchStateListener entry");
    std::shared_ptr<SwitchStateListenerImpl> switchStateNativeListener = std::make_shared<SwitchStateListenerImpl>(
        std::bind(&FormAppLockHelper::OnSwitchStateChanged, this, std::placeholders::_1));
    if (switchStateNativeListener == nullptr) {
        HILOG_ERROR("failed to create switchStateNativeListener");
        return false;
    }
    int32_t ret = AppLockManagerClient::GetInstance().RegisterSwitchStateListener(switchStateNativeListener);
    if (ret != ERR_OK) {
        HILOG_ERROR("RegisterAppProtectedStateListener failed, res is %d", ret);
        return ret;
    }
    HILOG_INFO("RegisterSwitchStateListener end");
    return SUBSYS_COMMON;
}

void FormAppLockHelper::OnSwitchStateChanged(
    const std::vector<AppSecurityPrivacy::AppLock::SwitchState>& switchState)
{
    HILOG_INFO("fms onSwitchStateChanged callback");
    int32_t res = ERR_OK;
    for (auto &state : switchState) {
        HILOG_INFO("switchState changed, bundleName is %s, appIndex is %d, isEnabled is %d",
            state.appInfo.bundleName.c_str(), state.appInfo.appIndex, state.isEnabled);
        if (state.appInfo.appIndex != 0) {
            continue;
        }

        res = FormMgrAdapter::GetInstance().LockForms(state.appInfo.bundleName, state.userId, state.isEnabled);
        if (res != ERR_OK) {
            HILOG_ERROR("EnableForms is failed, res is %d", res);
        }
    }
    return;
}
}  // namespace AppExecFwk
}  // namespace OHOS
