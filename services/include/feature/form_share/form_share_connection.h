/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H

#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormShareConnection
 * Form share connection stub.
 */
class FormShareConnection : public FormAbilityConnection {
public:
    FormShareConnection(int64_t formId, const std::string &bundleName, const std::string &abilityName,
        const std::string &deviceId, int64_t formShareRequestCode, const int32_t userId);
    virtual ~FormShareConnection() = default;

protected:
    /**
     * @brief Error handling when connection fails.
     *        Share connection sends error response on failure.
     * @param resultCode Error code.
     * @param element Connection element.
     */
    void OnConnectError(int resultCode, const AppExecFwk::ElementName &element) override;

    /**
     * @brief Build task Want parameter with share request code.
     * @return Built Want object.
     */
    Want OnBuildTaskWant() override;

    /**
     * @brief Execute share acquire task after connection success.
     * @param want Task Want parameter.
     * @param remoteObject Remote object.
     */
    void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) override;

private:
    int64_t formId_;
    std::string remoteDeviceId_;
    int64_t formShareRequestCode_;
    DISALLOW_COPY_AND_MOVE(FormShareConnection);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_CONNECTION_H