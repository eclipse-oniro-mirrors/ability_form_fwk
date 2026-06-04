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

#ifndef OHOS_FORM_FWK_FORM_REFRESH_CONNECTION_H
#define OHOS_FORM_FWK_FORM_REFRESH_CONNECTION_H

#include "common/connection/form_ability_connection.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormRefreshConnection
 * Form Refresh Connection Stub.
 */
class FormRefreshConnection : public FormAbilityConnection {
public:
    FormRefreshConnection(const int64_t formId, const Want &want, const std::string &bundleName,
        const std::string &abilityName, bool isFreeInstall, const int32_t userId);
    virtual ~FormRefreshConnection() = default;

protected:
    /**
     * @brief Whether freeInstall processing is needed.
     *        Refresh connection needs freeInstall processing.
     * @return true.
     */
    bool NeedFreeInstallProcessing() const override { return true; }

    /**
     * @brief Pre-processing after connection success.
     *        Marks connected state for dual-signal precondition check.
     */
    void OnPreConnectTask() override;

    /**
     * @brief Build task Want parameter based on refresh type.
     * @return Built Want object.
     */
    Want OnBuildTaskWant() override;

    /**
     * @brief Execute refresh task after connection success.
     *        Handles message event, recreate form, and refresh form scenarios.
     * @param want Task Want parameter.
     * @param remoteObject Remote object.
     */
    void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) override;

    /**
     * @brief Override: DISCONNECT_ERROR+CONNECTED triggers HandleDisconnectError.
     *        Calls base OnAbilityDisconnectDone first, then checks dual-signal condition.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

private:
    Want want_;
    ConnectState connectState_ = ConnectState::DISCONNECTED;
    DISALLOW_COPY_AND_MOVE(FormRefreshConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_REFRESH_CONNECTION_H