/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_NET_CONN_CALLBACK_MANAGER_H
#define OHOS_FORM_FWK_NET_CONN_CALLBACK_MANAGER_H

#include <memory>
#include <singleton.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Network connection callback manager for FormMgrService.
 * Manages network callback registration and unregistration.
 */
class NetConnCallbackManager {
    DECLARE_DELAYED_SINGLETON(NetConnCallbackManager);
    DISALLOW_COPY_AND_MOVE(NetConnCallbackManager);

public:
    /**
     * @brief Register network connection callback
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t RegisterNetConnCallback();

    /**
     * @brief Unregister network connection callback
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t UnregisterNetConnCallback();

private:
private:
    /**
     * @brief Post delayed network connection task
     */
    void PostConnectNetWork();

    std::atomic<int32_t> netConTime_;
    std::atomic<bool> isRegistered_;
};
} // AppExecFwk
} // OHOS
#endif // OHOS_FORM_FWK_NET_CONN_CALLBACK_MANAGER_H
