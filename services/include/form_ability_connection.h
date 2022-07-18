/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_ABILITY_CONNECTION_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_ABILITY_CONNECTION_H

#include "provider_connect_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using WantParams = OHOS::AAFwk::WantParams;

/**
 * @class FormAbilityConnection
 * Form Ability Connection Stub.
 */
class FormAbilityConnection : public ProviderConnectStub {
public:
    FormAbilityConnection() = default;
    virtual ~FormAbilityConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     * @param element service ability's ElementName.
     * @param remoteObject the session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    virtual void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     * @param element service ability's ElementName.
     * @param resultCode ERR_OK on success, others on failure.
     */
    virtual void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    /**
     * @brief remote object died event.
     * @param remoteObject the remote object of service ability.
     */
    void OnConnectDied(const wptr<IRemoteObject> &remoteObject);

    /**
     * @brief Get connectId.
     * @return The ability connection id.
     */
    long GetConnectId() const;

    /**
     * @brief Set connectId.
     * @param connectId The ability connection id.
     */
    void SetConnectId(long connectId);
    /**
     * @brief Get the provider Key
     *
     * @return The provider Key
     */
    std::string GetProviderKey() const;
    /**
     * @brief Set the Provider Key
     *
     * @param bundleName bundleName
     * @param abilityName abilityName
     */
    void SetProviderKey(const std::string &bundleName, const std::string &abilityName);

    /**
     * @brief Set free install true or false.
     *
     * @param isFreeInstall Indicates the free install flag is true or false.
     */
    void SetFreeInstall(bool isFreeInstall);

    /**
     * @brief Set form ID.
     *
     * @param formId Indicates the form ID.
     */
    void SetFormId(int64_t formId);

    /**
     * @brief Get form ID.
     */
    int64_t GetFormId() const;
private:
    int64_t formId_ = -1;
    std::string deviceId_ = "";
    std::string bundleName_ = "";
    std::string abilityName_ = "";
    bool isFreeInstall_ = false;
    long connectId_ = 0;

    DISALLOW_COPY_AND_MOVE(FormAbilityConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_ABILITY_CONNECTION_H
