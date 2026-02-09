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

#ifndef OHOS_FORM_FWK_FORM_AMS_HELPER_H
#define OHOS_FORM_FWK_FORM_AMS_HELPER_H

#include <singleton.h>

#include "ability_connect_callback_interface.h"
#include "ability_manager_interface.h"
#include "common/event/form_event_handler.h"
#include "common/util/form_serial_queue.h"
#include "iconfiguration_observer.h"
#include "uri.h"

namespace OHOS {
namespace AppExecFwk {
using IAbilityConnection = OHOS::AAFwk::IAbilityConnection;
using Want = OHOS::AAFwk::Want;
const int FORM_DISCONNECT_DELAY_TIME = 10000; // ms
/**
 * @class FormAmsHelper
 * Ams helpler.
 */
class FormAmsHelper final : public DelayedRefSingleton<FormAmsHelper> {
    DECLARE_DELAYED_REF_SINGLETON(FormAmsHelper)
public:
    DISALLOW_COPY_AND_MOVE(FormAmsHelper);
    /**
     * @brief acquire a form ability manager if it not existed,
     * @return returns the ability manager ipc object or nullptr for failed.
     */
    sptr<AAFwk::IAbilityManager> GetAbilityManager();
    /**
     * @brief Connect session with service ability.
     * @param want Special want for service type's ability.
     * @param connect Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectServiceAbility(
        const Want &want, const sptr<AAFwk::IAbilityConnection> &connect);
    /**
     * @brief Connect session with service ability.
     * @param want Special want for service type's ability.
     * @param connect Callback used to notify caller the result of connecting or disconnecting.
     * @param userId Designation User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ConnectServiceAbilityWithUserId(
        const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId);
    /**
     * @brief Disconnect session with service ability.
     * @param connect Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DisconnectServiceAbility(const sptr<AAFwk::IAbilityConnection> &connect);
    /**
     * @brief Disconnect ability delay, disconnect session with service ability.
     * @param connect Callback used to notify caller the result of connecting or disconnecting.
     * @param delayTime Special time to delay, default is FORM_DISCONNECT_DELAY_TIME.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DisconnectServiceAbilityDelay(
        const sptr<AAFwk::IAbilityConnection> &connect, int delayTime = FORM_DISCONNECT_DELAY_TIME);
    /**
     * @brief StartAbility with want, send want to ability manager service.
     * @param want The want of the ability to start.
     * @param userId Designation User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StartAbility(const Want &want, int32_t userId);
    /**
     * @brief Add the ability manager instance for debug.
     * @param abilityManager the ability manager ipc object.
     */
    void SetAbilityManager(const sptr<AAFwk::IAbilityManager> &abilityManager);
    /**
     * @brief StopExtensionAbility with want, send want to ability manager service.
     * @param want The want of the ability to start.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StopExtensionAbility(const Want &want);
    /**
     * @brief register Configuration Observer.
     */
    void RegisterConfigurationObserver();
    /**
     * @brief unregister Configuration Observer.
     */
    void UnRegisterConfigurationObserver();
    /**
     * @brief StartAbilityOnlyUIAbility with want, send want to ability manager service.
     * @param want The want of the ability to start.
     * @param userId Designation User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StartAbilityOnlyUIAbility(Want &want, const sptr<IRemoteObject> &callerToken,
        const int32_t userId);
private:
    /**
     * @brief Disconnect ability task, disconnect session with service ability.
     * @param want Special want for service type's ability.
     * @param connect Callback used to notify caller the result of connecting or disconnecting.
     */
    void DisconnectAbilityTask(const sptr<AAFwk::IAbilityConnection> &connect);
private:
    sptr<AAFwk::IAbilityManager> abilityManager_ = nullptr;
    sptr<IConfigurationObserver> configurationObserver_ = nullptr;
    std::mutex configObserverMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_AMS_HELPER_H
