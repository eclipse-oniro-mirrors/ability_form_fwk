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

#include <atomic>

#include "common/connection/form_ability_connection.h"
#include "data_center/form_record/form_record.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormRefreshConnection
 * Form Refresh Connection Stub.
 */
class FormRefreshConnection : public FormAbilityConnection {
public:
    FormRefreshConnection(const int64_t formId, const Want &want, const FormRecord &record);
    virtual ~FormRefreshConnection() = default;

    /**
     * @brief Create retry connection for delayed retry policy.
     *        Creates a new FormRefreshConnection with same formId, want, and record.
     * @return Retry FormRefreshConnection object (sptr<FormAbilityConnection>).
     */
    sptr<FormAbilityConnection> CreateRetryConnection() const override;

protected:
    /**
     * @brief Whether freeInstall processing is needed.
     *        Refresh connection needs freeInstall processing.
     * @return true.
     */
    bool NeedFreeInstallProcessing() const override { return true; }

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
     * @param element Element name of the ability.
     * @param resultCode Result code of disconnect operation.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

private:
    Want want_;
    FormRecord record_;
    DISALLOW_COPY_AND_MOVE(FormRefreshConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_REFRESH_CONNECTION_H