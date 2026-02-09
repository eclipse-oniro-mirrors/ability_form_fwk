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

#include "ams_mgr/form_ams_helper.h"

#include "ability_manager_interface.h"
#include "app_mgr_client.h"
#include "form_observer/form_resource_observer.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/util/form_serial_queue.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "form_mgr/form_mgr_queue.h"

namespace OHOS {
namespace AppExecFwk {
FormAmsHelper::FormAmsHelper()
{}

FormAmsHelper::~FormAmsHelper()
{}

/**
 * @brief acquire a form ability manager, if it not existed,
 * @return returns the ability manager ipc object, or nullptr for failed.
 */
sptr<AAFwk::IAbilityManager> FormAmsHelper::GetAbilityManager()
{
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
        HILOG_DEBUG("connect AbilityMgrService success");

        abilityManager_ = iface_cast<AAFwk::IAbilityManager>(remoteObject);
    }

    return abilityManager_;
}

/**
 * @brief ConnectAbility, connect session with service ability.
 * @param want Special want for service type's ability.
 * @param connect Callback used to notify caller the result of connecting or disconnecting.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    HILOG_DEBUG("connect service ability");
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return IN_PROCESS_CALL(ams->ConnectAbility(want, connect, nullptr));
}

/**
 * @brief ConnectAbility, connect session with service ability.
 * @param want Special want for service type's ability.
 * @param connect Callback used to notify caller the result of connecting or disconnecting.
 * @param userId Designation User ID.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormAmsHelper::ConnectServiceAbilityWithUserId(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId)
{
    HILOG_DEBUG("connect service ability with userId");
    sptr<AAFwk::IAbilityManager> abilityManagerService = GetAbilityManager();
    if (abilityManagerService == nullptr) {
        HILOG_ERROR("ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return IN_PROCESS_CALL(abilityManagerService->ConnectAbility(want, connect, nullptr, userId));
}

/**
 * @brief Disconnect ability, disconnect session with service ability.
 * @param connect Callback used to notify caller the result of connecting or disconnecting.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormAmsHelper::DisconnectServiceAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    HILOG_INFO("call");
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return IN_PROCESS_CALL(ams->DisconnectAbility(connect));
}
/**
 * @brief Disconnect ability delay, disconnect session with service ability.
 * @param connect Callback used to notify caller the result of connecting or disconnecting.
 * @param delayTime Specifying time to delay, default is FORM_DISCONNECT_DELAY_TIME.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormAmsHelper::DisconnectServiceAbilityDelay(const sptr<AAFwk::IAbilityConnection> &connect, int delayTime)
{
    auto disConnectAbilityFunc = [connect]() {
        FormAmsHelper::GetInstance().DisconnectAbilityTask(connect);
    };
    if (!FormMgrQueue::GetInstance().ScheduleTask(delayTime, disConnectAbilityFunc)) {
        HILOG_ERROR("fail disconnect ability");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}
/**
 * @brief StopExtensionAbility with want, send want to ability manager service.
 * @param want The want of the ability to start.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormAmsHelper::StopExtensionAbility(const Want &want)
{
    HILOG_DEBUG("call");
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("StopExtensionAbility ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return IN_PROCESS_CALL(ams->StopExtensionAbility(want, nullptr));
}
/**
 * @brief Add the ability manager instance for debug.
 * @param abilityManager the ability manager ipc object.
 */
void FormAmsHelper::SetAbilityManager(const sptr<AAFwk::IAbilityManager> &abilityManager)
{
    abilityManager_ = abilityManager;
}

/**
 * @brief Disconnect ability task, disconnect session with service ability.
 * @param want Special want for service type's ability.
 * @param connect Callback used to notify caller the result of connecting or disconnecting.
 */
void FormAmsHelper::DisconnectAbilityTask(const sptr<AAFwk::IAbilityConnection> &connect)
{
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("ability service not connect");
        return;
    }
    IN_PROCESS_CALL_WITHOUT_RET(ams->DisconnectAbility(connect));
}

ErrCode FormAmsHelper::StartAbility(const Want &want, int32_t userId)
{
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return IN_PROCESS_CALL(ams->StartAbility(want, userId));
}

void FormAmsHelper::RegisterConfigurationObserver()
{
    HILOG_INFO("begin");
    std::lock_guard<std::mutex> lock(configObserverMutex_);
    if (configurationObserver_ != nullptr) {
        HILOG_WARN("configurationObserver_ not null");
        return;
    }
    sptr<IConfigurationObserver> configurationObserver(new (std::nothrow) FormFwkResourceObserver());
    if (configurationObserver == nullptr) {
        HILOG_ERROR("create configurationObserver failed");
        return;
    }
    auto appMgrClient = std::make_unique<AppMgrClient>();
    if (appMgrClient == nullptr) {
        HILOG_ERROR("create appMgrClient failed");
        return;
    }
    AppMgrResultCode resCode = appMgrClient->RegisterConfigurationObserver(configurationObserver);
    if (resCode != AppMgrResultCode::RESULT_OK) {
        HILOG_ERROR("RegisterConfigurationObserver failed");
        return;
    }
    configurationObserver_ = configurationObserver;
    HILOG_INFO("end");
}

void FormAmsHelper::UnRegisterConfigurationObserver()
{
    HILOG_INFO("begin");
    std::lock_guard<std::mutex> lock(configObserverMutex_);
    if (configurationObserver_ == nullptr) {
        HILOG_WARN("null configurationObserver_");
        return;
    }
    auto appMgrClient = std::make_unique<AppMgrClient>();
    if (appMgrClient == nullptr) {
        HILOG_ERROR("create appMgrClient failed");
        return;
    }
    AppMgrResultCode resCode = appMgrClient->UnregisterConfigurationObserver(configurationObserver_);
    if (resCode != AppMgrResultCode::RESULT_OK) {
        HILOG_ERROR("UnregisterConfigurationObserver failed");
        return;
    }
    configurationObserver_ = nullptr;
    HILOG_INFO("end");
}

ErrCode FormAmsHelper::StartAbilityOnlyUIAbility(Want &want, const sptr<IRemoteObject> &callerToken,
    const int32_t userId)
{
    sptr<AAFwk::IAbilityManager> ams = GetAbilityManager();
    if (ams == nullptr) {
        HILOG_ERROR("ability service not connect");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    InsightIntentExecuteParam::RemoveInsightIntent(want);
    auto flags = want.GetFlags();
    if ((flags & Want::FLAG_ABILITY_CONTINUATION) == Want::FLAG_ABILITY_CONTINUATION) {
        HILOG_ERROR("StartAbility not allowed:%{public}d", ERR_APPEXECFWK_FORM_INVALID_PARAM);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return IN_PROCESS_CALL(ams->StartAbility(want, callerToken, userId));
}
}  // namespace AppExecFwk
}  // namespace OHOS
