/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_SERVICE_DISCOVERY_H
#define OHOS_FORM_FWK_FORM_SERVICE_DISCOVERY_H

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "feature/cross_device_publish/dm_service_adapter.h"
#include "feature/service_gateway/form_publish_router.h"
#include "feature/service_discovery/form_service_proxy.h"
#include "form_service_info.h"
#include "peer_form_service_info.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {

// Pure DM query: GetTrustServiceInfo → filter online trusted → translate to PeerFormHostServiceInfo.
// No SoftBus connections needed for discovery.
// Owns FormServiceProxy and IDmServiceAdapter as unified entry point.
class FormServiceDiscovery final : public DelayedRefSingleton<FormServiceDiscovery> {
    DECLARE_DELAYED_REF_SINGLETON(FormServiceDiscovery)

public:
    DISALLOW_COPY_AND_MOVE(FormServiceDiscovery);

    ErrCode Register(const FormHostServiceInfo &info, int64_t &serviceId);
    ErrCode Unregister(int64_t serviceId);

    // DM GetTrustedDeviceList → GetTrustServiceInfo → translate to PeerFormHostServiceInfo
    ErrCode GetAvailableFormHostServices(std::vector<PeerFormHostServiceInfo> &services);

    bool GetUserIdByServiceId(int64_t serviceId, int32_t &userId);
    bool IsDiscoveredPeer(const std::string &networkId, int64_t serviceId);
    void Dump(std::string &result);

private:
    void EnsureMembers();
    void TranslateDmServiceToPeer(const DistributedHardware::DmServiceInfo &dmSvc,
        PeerFormHostServiceInfo &peerInfo);
    std::unordered_set<std::string> CollectIdenticalNetworkIds(
        const std::vector<DistributedHardware::DmDeviceInfo> &onlineDevices);
    void FilterPeerServices(const std::vector<DistributedHardware::DmServiceInfo> &dmServices,
        const std::unordered_set<std::string> &identicalIds,
        std::vector<PeerFormHostServiceInfo> &services);

    std::once_flag initOnce_;
    std::shared_ptr<IDmServiceAdapter> dmAdapter_;
    std::shared_ptr<FormServiceProxy> serviceProxy_;
    std::mutex discoveryMutex_;
    std::unordered_set<std::string> discoveredPeerKeys_;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SERVICE_DISCOVERY_H
