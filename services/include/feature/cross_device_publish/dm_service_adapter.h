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

#ifndef OHOS_FORM_FWK_DM_SERVICE_ADAPTER_H
#define OHOS_FORM_FWK_DM_SERVICE_ADAPTER_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "device_manager.h"
#include "device_manager_callback.h"
#include "dm_device_info.h"
#include "errors.h"

namespace OHOS {
namespace AppExecFwk {

// Decouples FormServiceProxy and FormServiceDiscovery from the DM SDK.
class IDmServiceAdapter {
public:
    virtual ~IDmServiceAdapter() = default;

    virtual int32_t InitDeviceManager(const std::string &pkgName,
        std::shared_ptr<DistributedHardware::DmInitCallback> callback) = 0;

    virtual int32_t RegisterServiceInfo(const DistributedHardware::DmRegisterServiceInfo &regInfo,
        int64_t &serviceId) = 0;

    virtual int32_t UnRegisterServiceInfo(int64_t serviceId) = 0;

    virtual int32_t StartPublishService(const std::string &pkgName, int64_t serviceId,
        const DistributedHardware::DmPublishServiceParam &publishServiceParam,
        std::shared_ptr<DistributedHardware::ServicePublishCallback> callback) = 0;

    virtual int32_t StopPublishService(const std::string &pkgName, int64_t serviceId) = 0;

    virtual int32_t GetTrustServiceInfo(const std::string &pkgName,
        const std::map<std::string, std::string> &param,
        std::vector<DistributedHardware::DmServiceInfo> &serviceInfo) = 0;

    virtual int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DistributedHardware::DmDeviceInfo> &deviceList) = 0;

    virtual int32_t GetLocalDeviceNetworkId(const std::string &pkgName, std::string &networkId) = 0;

    virtual int32_t GetLocalDeviceName(const std::string &pkgName, std::string &deviceName) = 0;

    virtual int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &networkId, std::string &udid) = 0;
};

class DmServiceAdapter : public IDmServiceAdapter {
public:
    DmServiceAdapter() = default;
    ~DmServiceAdapter() override = default;

    int32_t InitDeviceManager(const std::string &pkgName,
        std::shared_ptr<DistributedHardware::DmInitCallback> callback) override;

    int32_t RegisterServiceInfo(const DistributedHardware::DmRegisterServiceInfo &regInfo,
        int64_t &serviceId) override;

    int32_t UnRegisterServiceInfo(int64_t serviceId) override;

    int32_t StartPublishService(const std::string &pkgName, int64_t serviceId,
        const DistributedHardware::DmPublishServiceParam &publishServiceParam,
        std::shared_ptr<DistributedHardware::ServicePublishCallback> callback) override;

    int32_t StopPublishService(const std::string &pkgName, int64_t serviceId) override;

    int32_t GetTrustServiceInfo(const std::string &pkgName,
        const std::map<std::string, std::string> &param,
        std::vector<DistributedHardware::DmServiceInfo> &serviceInfo) override;

    int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DistributedHardware::DmDeviceInfo> &deviceList) override;

    int32_t GetLocalDeviceNetworkId(const std::string &pkgName, std::string &networkId) override;

    int32_t GetLocalDeviceName(const std::string &pkgName, std::string &deviceName) override;

    int32_t GetUdidByNetworkId(const std::string &pkgName, const std::string &networkId, std::string &udid) override;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_DM_SERVICE_ADAPTER_H
