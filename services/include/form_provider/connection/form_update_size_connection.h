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

#ifndef OHOS_FORM_FWK_FORM_UPDATE_SIZE_CONNECTION_H
#define OHOS_FORM_FWK_FORM_UPDATE_SIZE_CONNECTION_H

#include "common/connection/form_ability_connection.h"
#include "want.h"
#include "form_instance.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

/**
 * @class FormUpdateSizeConnection
 * Form update size Connection Stub.
 */
class FormUpdateSizeConnection : public FormAbilityConnection {
public:
    FormUpdateSizeConnection(const int64_t formId, const std::string &bundleName, const std::string &abilityName,
        const int32_t newDimension, const Rect &newRect, const int32_t userId);
    virtual ~FormUpdateSizeConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     * @param element service ability's ElementName.
     * @param remoteObject the session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int resultCode) override;

private:
    Want want_;
    int32_t newDimension_;
    Rect newRect_;
    DISALLOW_COPY_AND_MOVE(FormUpdateSizeConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_UPDATE_SIZE_CONNECTION_H