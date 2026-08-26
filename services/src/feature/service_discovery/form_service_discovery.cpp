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

#include "feature/service_discovery/form_service_discovery.h"

#include <cinttypes>
#include <chrono>
#include <string>
#include <unordered_set>

#include "device_manager_callback.h"
#include "form_cross_device_constants.h"
#include "form_mgr_errors.h"
#include "form_service_constants.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::DistributedHardware;
namespace {
class FormServiceDmInitCallback : public DmInitCallback {
public:
    void OnRemoteDied() override
    {
        HILOG_ERROR("device manager service died, cross-device features may be unavailable");
    }
};
} // namespace

FormServiceDiscovery::FormServiceDiscovery() = default;

FormServiceDiscovery::~FormServiceDiscovery() = default;

void FormServiceDiscovery::EnsureMembers()
{
    std::call_once(initOnce_, [this]() {
        dmAdapter_ = std::make_shared<DmServiceAdapter>();

        // Inject SoftBus transport hooks: StartListen/StopListen from FormPublishRouter
        ServiceTransportHooks hooks;
        hooks.onStartListen = [](int64_t serviceId) -> ErrCode {
            return FormPublishRouter::GetInstance().StartListen(serviceId);
        };
        hooks.onStopListen = [](int64_t serviceId) {
            FormPublishRouter::GetInstance().StopListen(serviceId);
        };

        serviceProxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, hooks);

        // DM initialization for service discovery queries
        int32_t dmRet = dmAdapter_->InitDeviceManager(
            FORM_SERVICE_OWNER_PKG, std::make_shared<FormServiceDmInitCallback>());
        if (dmRet != 0) {
            HILOG_WARN("InitDeviceManager failed %{public}d, service discovery may fail until DM ready", dmRet);
        }
    });
}

ErrCode FormServiceDiscovery::Register(const FormHostServiceInfo &info, int64_t &serviceId)
{
    EnsureMembers();
    return serviceProxy_->Register(info, serviceId);
}

ErrCode FormServiceDiscovery::Unregister(int64_t serviceId)
{
    EnsureMembers();
    return serviceProxy_->Unregister(serviceId);
}

ErrCode FormServiceDiscovery::GetAvailableFormHostServices(std::vector<PeerFormHostServiceInfo> &services)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    EnsureMembers();
    HILOG_INFO("GetAvailableFormHostServices enter");
    int64_t startTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    std::vector<DmDeviceInfo> onlineDevices;
    int32_t dmRet = dmAdapter_->GetTrustedDeviceList(FORM_SERVICE_OWNER_PKG, "", onlineDevices);
    if (dmRet != 0) {
        HILOG_ERROR("GetTrustedDeviceList failed:%{public}d", dmRet);
        return ERR_APPEXECFWK_FORM_SERVICE_DM_UNAVAILABLE;
    }

    std::unordered_set<std::string> identicalIds = CollectIdenticalNetworkIds(onlineDevices);

    std::map<std::string, std::string> param;
    param[FORM_SERVICE_PARAM_KEY_LOCAL_USER_ID] = std::to_string(FormUtil::GetCurrentAccountId());
    param[FORM_SERVICE_PARAM_KEY_IS_PROXY_QUERY] = "false";
    std::vector<DmServiceInfo> dmServices;
    dmRet = dmAdapter_->GetTrustServiceInfo(FORM_SERVICE_OWNER_PKG, param, dmServices);
    if (dmRet != 0) {
        HILOG_ERROR("GetTrustServiceInfo failed:%{public}d", dmRet);
        return ERR_APPEXECFWK_FORM_SERVICE_DM_UNAVAILABLE;
    }
    HILOG_INFO("GetTrustServiceInfo returned %{public}zu services", dmServices.size());

    FilterPeerServices(dmServices, identicalIds, services);

    int64_t totalElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() - startTime;
    HILOG_INFO("GetAvailableFormHostServices done: services=%{public}zu elapsed=%{public}" PRId64 "ms",
        services.size(), totalElapsed);
    return ERR_OK;
}

std::unordered_set<std::string> FormServiceDiscovery::CollectIdenticalNetworkIds(
    const std::vector<DmDeviceInfo> &onlineDevices)
{
    std::unordered_set<std::string> identicalIds;
    for (const auto &dev : onlineDevices) {
        HILOG_DEBUG("online device: {deviceId=%{private}s, deviceName=%{private}s, networkId=%{private}s"
            ", deviceTypeId=%{public}u, authForm=%{public}d}",
            dev.deviceId, dev.deviceName, dev.networkId,
            static_cast<uint32_t>(dev.deviceTypeId), static_cast<int32_t>(dev.authForm));
        if (dev.authForm == DmAuthForm::IDENTICAL_ACCOUNT) {
            identicalIds.emplace(dev.networkId);
        }
    }
    HILOG_INFO("IDENTICAL_ACCOUNT online=%{public}zu out of %{public}zu devices",
        identicalIds.size(), onlineDevices.size());
    return identicalIds;
}

void FormServiceDiscovery::FilterPeerServices(const std::vector<DmServiceInfo> &dmServices,
    const std::unordered_set<std::string> &identicalIds, std::vector<PeerFormHostServiceInfo> &services)
{
    {
        std::lock_guard<std::mutex> lock(discoveryMutex_);
        discoveredPeerKeys_.clear();
    }
    for (const auto &svc : dmServices) {
        HILOG_DEBUG("trusted service: networkId=%{public}s, serviceId=%{public}" PRId64
            ", serviceType=%{public}s, publishState=%{public}d, authform=%{public}d",
            svc.networkId.c_str(), svc.serviceId, svc.serviceType.c_str(),
            static_cast<int32_t>(svc.publishState), static_cast<int32_t>(svc.authform));
        if (svc.serviceType != FORM_CD_SERVICE_TYPE) {
            HILOG_DEBUG("skipped non-FMS service: serviceType=%{public}s", svc.serviceType.c_str());
            continue;
        }
        if (svc.publishState != DMPublishState::SERVICE_PUBLISHED_STATE) {
            HILOG_INFO("skipped unpublished service: networkId=%{public}s, publishState=%{public}d",
                svc.networkId.c_str(), static_cast<int32_t>(svc.publishState));
            continue;
        }
        if (identicalIds.count(svc.networkId) == 0) {
            HILOG_INFO("skipped offline or non-IDENTICAL_ACCOUNT service: networkId=%{public}s, authform=%{public}d",
                svc.networkId.c_str(), static_cast<int32_t>(svc.authform));
            continue;
        }
        PeerFormHostServiceInfo peerInfo;
        TranslateDmServiceToPeer(svc, peerInfo);
        {
            std::lock_guard<std::mutex> lock(discoveryMutex_);
            discoveredPeerKeys_.insert(peerInfo.networkId + ":" + peerInfo.serviceId);
        }
        services.push_back(std::move(peerInfo));
    }
}

bool FormServiceDiscovery::GetUserIdByServiceId(int64_t serviceId, int32_t &userId)
{
    EnsureMembers();
    return serviceProxy_->GetUserIdByServiceId(serviceId, userId);
}

bool FormServiceDiscovery::IsDiscoveredPeer(const std::string &networkId, int64_t serviceId)
{
    std::lock_guard<std::mutex> lock(discoveryMutex_);
    return discoveredPeerKeys_.count(networkId + ":" + std::to_string(serviceId)) > 0;
}

void FormServiceDiscovery::Dump(std::string &result)
{
    EnsureMembers();
    result += "== FormService ==\n";
    if (serviceProxy_ != nullptr) {
        serviceProxy_->Dump(result);
    }
}

void FormServiceDiscovery::TranslateDmServiceToPeer(const DmServiceInfo &dmSvc, PeerFormHostServiceInfo &peerInfo)
{
    peerInfo.serviceName = dmSvc.serviceName;
    peerInfo.serviceDisplayName = dmSvc.serviceDisplayName;
    peerInfo.displayId = std::to_string(dmSvc.displayId);
    peerInfo.customData = dmSvc.customData;
    peerInfo.networkId = dmSvc.networkId;
    peerInfo.serviceId = std::to_string(dmSvc.serviceId);

    // DmServiceInfo.deviceId is a hash value; resolve real UDID via GetUdidByNetworkId
    std::string udid;
    int32_t ret = dmAdapter_->GetUdidByNetworkId(FORM_SERVICE_OWNER_PKG, dmSvc.networkId, udid);
    if (ret == 0 && !udid.empty()) {
        peerInfo.deviceId = udid;
    } else {
        HILOG_WARN("GetUdidByNetworkId failed, fallback to dmSvc.deviceId, networkId=%{public}s, ret=%{public}d",
            dmSvc.networkId.c_str(), ret);
        peerInfo.deviceId = dmSvc.deviceId;
    }
}

} // namespace AppExecFwk
} // namespace OHOS
