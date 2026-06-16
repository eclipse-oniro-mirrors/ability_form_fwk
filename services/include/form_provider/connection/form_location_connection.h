/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_LOCATION_CONNECTION_H
#define OHOS_FORM_FWK_FORM_LOCATION_CONNECTION_H

#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormLocationConnection
 * Form location refresh Connection Stub.
 */
class FormLocationConnection : public FormAbilityConnection {
public:
    FormLocationConnection(const int64_t formId, const Want &want, const std::string &bundleName,
        const std::string &abilityName, const int32_t userId);
    virtual ~FormLocationConnection() = default;

protected:
    /**
     * @brief Whether freeInstall processing is needed.
     *        Location connection needs freeInstall processing.
     * @return true.
     */
    bool NeedFreeInstallProcessing() const override { return true; }

    /**
     * @brief Build task Want parameter with location info.
     * @return Built Want object.
     */
    Want OnBuildTaskWant() override;

    /**
     * @brief Execute location refresh task after connection success.
     * @param want Task Want parameter.
     * @param remoteObject Remote object.
     */
    void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) override;

private:
    Want want_;
    DISALLOW_COPY_AND_MOVE(FormLocationConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_LOCATION_CONNECTION_H