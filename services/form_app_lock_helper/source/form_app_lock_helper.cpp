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
#include "app_lock_manager_proxy.h"
#include "app_lock_manager_client.h"
#include "switch_state_listener.h"
#include "form_mgr_errors.h"
#include "form_mgr_adapter.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
    constexpr int APP_LOCK_MANAGER_SA_ID = 66288;
}
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
    OnSwitchStateChangedCbFunc onSwitchStateChanged =
        std::bind(&FormAppLockHelper::OnSwitchStateChanged, this, std::placeholders::_1);
    sptr<ISwitchStateListener> switchStateRemoteCallback =
        new (std::nothrow) SwitchStateListenerStubImpl(onSwitchStateChanged);
    WithCheckSystemAbility([this, switchStateRemoteCallback](const sptr<IAppLockManager> &proxy) {
        if (proxy == nullptr) {
            HILOG_ERROR("proxy is nullptr");
            return;
        }
        proxy->RegisterSwitchStateListener(switchStateRemoteCallback);
    });
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

void FormAppLockHelper::WithCheckSystemAbility(
    const std::function<void(const sptr<AppSecurityPrivacy::AppLock::IAppLockManager>&)>& consumer)
{
    auto saMgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgrProxy == nullptr) {
        HILOG_ERROR("saMgrProxy is nullptr!");
        consumer(nullptr);
        return;
    }
    auto sa = saMgrProxy->GetSystemAbility(APP_LOCK_MANAGER_SA_ID);
    ConsumeWithSystemAbility(consumer, sa);
}

void FormAppLockHelper::ConsumeWithSystemAbility(
    const std::function<void(const sptr<AppSecurityPrivacy::AppLock::IAppLockManager>&)>& consumer,
    const sptr<IRemoteObject>& sa)
{
    if (sa == nullptr) {
        HILOG_ERROR("sa= %{public}d is nullptr", APP_LOCK_MANAGER_SA_ID);
        consumer(nullptr);
        return;
    }
    if (sa->IsObjectDead()) {
        HILOG_ERROR("sa= %{public}d has dead", APP_LOCK_MANAGER_SA_ID);
        consumer(nullptr);
        return;
    }
    sptr<IAppLockManager> proxy = iface_cast<IAppLockManager>(sa);
    if (proxy == nullptr) {
        HILOG_ERROR("iface_cast sa= %{public}d is nullptr, there is nothing we can do.", APP_LOCK_MANAGER_SA_ID);
        consumer(nullptr);
        return;
    }
    HILOG_DEBUG("cast to AppLockManager succeed");
    consumer(proxy);
}
}  // namespace AppExecFwk
}  // namespace OHOS
