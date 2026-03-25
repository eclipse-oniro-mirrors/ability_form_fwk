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

#ifndef OHOS_FORM_FWK_NET_CONN_CALLBACK_OBSERVER_H
#define OHOS_FORM_FWK_NET_CONN_CALLBACK_OBSERVER_H

#include <memory>
#include <singleton.h>

#include "net_conn_callback_stub.h"
#include "net_handle.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Network connection callback observer for FormMgrService.
 * Observes network state changes and manages form updates based on network status.
 */
class NetConnCallbackObserver : public NetManagerStandard::NetConnCallbackStub {

public:
    explicit NetConnCallbackObserver();
    ~NetConnCallbackObserver() override = default;

    /**
     * @brief Set network connect status and update forms if needed
     */
    void SetNetConnect();

    /**
     * @brief Called when network is available
     * @param netHandle Network handle
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetAvailable(sptr<NetManagerStandard::NetHandle> &netHandle) override;

    /**
     * @brief Called when network capabilities change
     * @param netHandle Network handle
     * @param netAllCap Network capabilities
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
        const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap) override;

    /**
     * @brief Called when network connection properties change
     * @param netHandle Network handle
     * @param info Network link info
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetConnectionPropertiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
        const sptr<NetManagerStandard::NetLinkInfo> &info) override;

    /**
     * @brief Called when network is lost
     * @param netHandle Network handle
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetLost(sptr<NetManagerStandard::NetHandle> &netHandle) override;

    /**
     * @brief Called when network is unavailable
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetUnavailable() override;

    /**
     * @brief Called when network block status change
     * @param netHandle Network handle
     * @param blocked Whether network is blocked
     * @return Returns ERR_OK on success, error code on failure
     */
    int32_t NetBlockStatusChange(sptr<NetManagerStandard::NetHandle> &netHandle, bool blocked) override;

private:
    /**
     * @brief Set disconnect time for tracking network loss duration
     */
    void SetDisConnectTypeTime();

    std::atomic<int64_t> lastNetLostTime_;
};
} // AppExecFwk
} // OHOS
#endif // OHOS_FORM_FWK_NET_CONN_CALLBACK_OBSERVER_H
