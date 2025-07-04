/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_RENDER_CONNECTION_H
#define OHOS_FORM_FWK_FORM_RENDER_CONNECTION_H

#include <unordered_set>

#include "common/connection/form_ability_connection.h"
#include "data_center/form_info/form_item_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormRenderConnection
 * Form Render Connection Stub.
 */
class FormRenderConnection : public FormAbilityConnection {
public:
    FormRenderConnection(const FormRecord &formRecord, const WantParams &wantParams);
    FormRenderConnection() = delete; // disable default constructor.
    virtual ~FormRenderConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     *
     * @param element service ability's ElementName.
     * @param remoteObject the session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     * @param element service ability's ElementName.
     * @param resultCode ERR_OK on success, others on failure.
     */
    virtual void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    /**
     * @brief Set connectState to CONNECTING.
     */
    void SetStateConnecting();

    /**
     * @brief Set connectState to DISCONNECTED.
     */
    void SetStateDisconnected();

    void UpdateWantParams(const WantParams &wantParams);

    void UpdateFormRecord(const FormRecord &formRecord);

private:
    enum class ConnectState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
    };

    FormRecord formRecord_;
    WantParams wantParams_;
    ConnectState connectState_ = ConnectState::DISCONNECTED;
    int32_t failedTimes = 0;
    DISALLOW_COPY_AND_MOVE(FormRenderConnection);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_CONNECTION_H
