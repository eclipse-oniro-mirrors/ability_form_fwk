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

#include <gtest/gtest.h>

#include "feature/cross_device_publish/dm_service_adapter.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"

namespace {
int32_t g_getTrustedDeviceListRet = 0;
std::vector<OHOS::DistributedHardware::DmDeviceInfo> g_mockDeviceList;

int32_t g_getTrustServiceInfoRet = 0;
std::vector<OHOS::DistributedHardware::DmServiceInfo> g_mockServiceList;

int32_t g_getUdidRet = 0;
std::string g_mockUdid;

int32_t g_initDeviceManagerRet = 0;
} // namespace

namespace OHOS {
namespace AppExecFwk {

void MockGetTrustedDeviceList(int32_t ret,
    const std::vector<DistributedHardware::DmDeviceInfo> &devices)
{
    g_getTrustedDeviceListRet = ret;
    g_mockDeviceList = devices;
}

void MockGetTrustServiceInfo(int32_t ret,
    const std::vector<DistributedHardware::DmServiceInfo> &services)
{
    g_getTrustServiceInfoRet = ret;
    g_mockServiceList = services;
}

void MockGetUdidByNetworkId(int32_t ret, const std::string &udid)
{
    g_getUdidRet = ret;
    g_mockUdid = udid;
}

void MockInitDeviceManager(int32_t ret)
{
    g_initDeviceManagerRet = ret;
}

void ResetDmServiceAdapterMock()
{
    g_getTrustedDeviceListRet = 0;
    g_mockDeviceList.clear();
    g_getTrustServiceInfoRet = 0;
    g_mockServiceList.clear();
    g_getUdidRet = 0;
    g_mockUdid.clear();
    g_initDeviceManagerRet = 0;
}

int32_t DmServiceAdapter::InitDeviceManager(const std::string &pkgName,
    std::shared_ptr<DistributedHardware::DmInitCallback> callback)
{
    GTEST_LOG_(INFO) << "Mock InitDeviceManager ret=" << g_initDeviceManagerRet;
    return g_initDeviceManagerRet;
}

int32_t DmServiceAdapter::RegisterServiceInfo(
    const DistributedHardware::DmRegisterServiceInfo &regInfo, int64_t &serviceId)
{
    GTEST_LOG_(INFO) << "Mock RegisterServiceInfo";
    serviceId = 1;
    return 0;
}

int32_t DmServiceAdapter::UnRegisterServiceInfo(int64_t serviceId)
{
    GTEST_LOG_(INFO) << "Mock UnRegisterServiceInfo serviceId=" << serviceId;
    return 0;
}

int32_t DmServiceAdapter::StartPublishService(const std::string &pkgName, int64_t serviceId,
    const DistributedHardware::DmPublishServiceParam &publishServiceParam,
    std::shared_ptr<DistributedHardware::ServicePublishCallback> callback)
{
    GTEST_LOG_(INFO) << "Mock StartPublishService serviceId=" << serviceId;
    return 0;
}

int32_t DmServiceAdapter::StopPublishService(const std::string &pkgName, int64_t serviceId)
{
    GTEST_LOG_(INFO) << "Mock StopPublishService serviceId=" << serviceId;
    return 0;
}

int32_t DmServiceAdapter::GetTrustServiceInfo(const std::string &pkgName,
    const std::map<std::string, std::string> &param,
    std::vector<DistributedHardware::DmServiceInfo> &serviceInfo)
{
    GTEST_LOG_(INFO) << "Mock GetTrustServiceInfo ret=" << g_getTrustServiceInfoRet;
    if (g_getTrustServiceInfoRet == 0) {
        serviceInfo = g_mockServiceList;
    }
    return g_getTrustServiceInfoRet;
}

int32_t DmServiceAdapter::GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
    std::vector<DistributedHardware::DmDeviceInfo> &deviceList)
{
    GTEST_LOG_(INFO) << "Mock GetTrustedDeviceList ret=" << g_getTrustedDeviceListRet;
    if (g_getTrustedDeviceListRet == 0) {
        deviceList = g_mockDeviceList;
    }
    return g_getTrustedDeviceListRet;
}

int32_t DmServiceAdapter::GetLocalDeviceNetworkId(const std::string &pkgName, std::string &networkId)
{
    networkId = "local-network-id";
    return 0;
}

int32_t DmServiceAdapter::GetLocalDeviceName(const std::string &pkgName, std::string &deviceName)
{
    deviceName = "local-device-name";
    return 0;
}

int32_t DmServiceAdapter::GetUdidByNetworkId(const std::string &pkgName,
    const std::string &networkId, std::string &udid)
{
    GTEST_LOG_(INFO) << "Mock GetUdidByNetworkId ret=" << g_getUdidRet << " udid=" << g_mockUdid;
    if (g_getUdidRet == 0) {
        udid = g_mockUdid;
    }
    return g_getUdidRet;
}

} // namespace AppExecFwk
} // namespace OHOS
