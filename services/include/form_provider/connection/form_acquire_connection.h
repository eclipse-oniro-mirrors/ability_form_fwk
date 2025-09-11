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

#ifndef OHOS_FORM_FWK_FORM_ACQUIRE_CONNECTION_H
#define OHOS_FORM_FWK_FORM_ACQUIRE_CONNECTION_H

#include "event_handler.h"
#include "common/connection/form_ability_connection.h"
#include "data_center/form_info/form_item_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using WantParams = OHOS::AAFwk::WantParams;

/**
 * @class FormAcquireConnection
 * Form Acquire Connection Stub.
 */
class FormAcquireConnection : public FormAbilityConnection {
public:
    FormAcquireConnection(const int64_t formId, const FormItemInfo &info, const WantParams &wantParams,
        const sptr<IRemoteObject> hostToken);
    FormAcquireConnection() = delete; // disable default constructor.
    virtual ~FormAcquireConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     * @param element service ability's ElementName.
     * @param remoteObject the session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     * @param element service ability's ElementName.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    /**
     * @brief Set form ability connection callback.
     */
    void SetFormAbilityConnectCb(std::function<void(const std::string &bundleName)> &&callback);

    /**
     * @brief Set form ability disconnection callback.
     */
    void SetFormAbilityDisconnectCb(std::function<void(const std::string &bundleName)> &&callback);

    /**
     * @brief On form ability connect callback.
     */
    void OnFormAbilityConnectDoneCallback();

    /**
     * @brief On form ability disconnect callback.
     */
    void OnFormAbilityDisconnectDoneCallback();

private:
    FormItemInfo info_;
    WantParams wantParams_;
    bool isConnected_ = false;
    std::function<void(const std::string &bundleName)> onFormAblityConnectCb_;
    std::function<void(const std::string &bundleName)> onFormAblityDisconnectCb_;

    DISALLOW_COPY_AND_MOVE(FormAcquireConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ACQUIRE_CONNECTION_H
