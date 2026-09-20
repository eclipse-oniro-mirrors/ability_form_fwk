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

int32_t g_registerServiceInfoRet = 0;
int64_t g_registerServiceInfoId = 1;

int32_t g_startPublishServiceRet = 0;
int32_t g_stopPublishServiceRet = 0;
int32_t g_unRegisterServiceInfoRet = 0;

int32_t g_unRegisterServiceInfoCallCount = 0;
int32_t g_stopPublishServiceCallCount = 0;
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

void MockRegisterServiceInfo(int32_t ret, int64_t serviceId)
{
    g_registerServiceInfoRet = ret;
    g_registerServiceInfoId = serviceId;
}

void MockStartPublishService(int32_t ret)
{
    g_startPublishServiceRet = ret;
}

void MockStopPublishService(int32_t ret)
{
    g_stopPublishServiceRet = ret;
}

void MockUnRegisterServiceInfo(int32_t ret)
{
    g_unRegisterServiceInfoRet = ret;
}

int32_t GetUnRegisterServiceInfoCallCount()
{
    return g_unRegisterServiceInfoCallCount;
}

int32_t GetStopPublishServiceCallCount()
{
    return g_stopPublishServiceCallCount;
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
    g_registerServiceInfoRet = 0;
    g_registerServiceInfoId = 1;
    g_startPublishServiceRet = 0;
    g_stopPublishServiceRet = 0;
    g_unRegisterServiceInfoRet = 0;
    g_unRegisterServiceInfoCallCount = 0;
    g_stopPublishServiceCallCount = 0;
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
    GTEST_LOG_(INFO) << "Mock RegisterServiceInfo ret=" << g_registerServiceInfoRet;
    serviceId = g_registerServiceInfoId;
    return g_registerServiceInfoRet;
}

int32_t DmServiceAdapter::UnRegisterServiceInfo(int64_t serviceId)
{
    GTEST_LOG_(INFO) << "Mock UnRegisterServiceInfo serviceId=" << serviceId;
    ++g_unRegisterServiceInfoCallCount;
    return g_unRegisterServiceInfoRet;
}

int32_t DmServiceAdapter::StartPublishService(const std::string &pkgName, int64_t serviceId,
    const DistributedHardware::DmPublishServiceParam &publishServiceParam,
    std::shared_ptr<DistributedHardware::ServicePublishCallback> callback)
{
    GTEST_LOG_(INFO) << "Mock StartPublishService serviceId=" << serviceId;
    return g_startPublishServiceRet;
}

int32_t DmServiceAdapter::StopPublishService(const std::string &pkgName, int64_t serviceId)
{
    GTEST_LOG_(INFO) << "Mock StopPublishService serviceId=" << serviceId;
    ++g_stopPublishServiceCallCount;
    return g_stopPublishServiceRet;
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
    GTEST_LOG_(INFO) << "Mock GetUdidByNetworkId ret=" << g_getUdidRet;
    if (g_getUdidRet == 0) {
        udid = g_mockUdid;
    }
    return g_getUdidRet;
}

} // namespace AppExecFwk
} // namespace OHOS
