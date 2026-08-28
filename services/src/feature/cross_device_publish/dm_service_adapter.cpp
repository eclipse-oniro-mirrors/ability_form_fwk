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

#include "feature/cross_device_publish/dm_service_adapter.h"

#include "device_manager.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

int32_t DmServiceAdapter::InitDeviceManager(const std::string &pkgName,
    std::shared_ptr<DistributedHardware::DmInitCallback> callback)
{
    if (callback == nullptr) {
        HILOG_ERROR("InitDeviceManager callback is nullptr");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().InitDeviceManager(pkgName, callback);
    if (ret != 0) {
        HILOG_ERROR("InitDeviceManager failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

int32_t DmServiceAdapter::RegisterServiceInfo(const DistributedHardware::DmRegisterServiceInfo &regInfo,
    int64_t &serviceId)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().RegisterServiceInfo(regInfo, serviceId);
    if (ret != 0) {
        HILOG_ERROR("RegisterServiceInfo failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t DmServiceAdapter::UnRegisterServiceInfo(int64_t serviceId)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().UnRegisterServiceInfo(serviceId);
    if (ret != 0) {
        HILOG_ERROR("UnRegisterServiceInfo failed, serviceId=%{public}" PRId64 ", ret=%{public}d", serviceId, ret);
    }
    return ret;
}

int32_t DmServiceAdapter::StartPublishService(const std::string &pkgName, int64_t serviceId,
    const DistributedHardware::DmPublishServiceParam &publishServiceParam,
    std::shared_ptr<DistributedHardware::ServicePublishCallback> callback)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().StartPublishService(
        pkgName, serviceId, publishServiceParam, callback);
    if (ret != 0) {
        HILOG_ERROR("StartPublishService failed, pkgName=%{public}s, serviceId=%{public}" PRId64 ", ret=%{public}d",
            pkgName.c_str(), serviceId, ret);
    }
    return ret;
}

int32_t DmServiceAdapter::StopPublishService(const std::string &pkgName, int64_t serviceId)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().StopPublishService(pkgName, serviceId);
    if (ret != 0) {
        HILOG_ERROR("StopPublishService failed, pkgName=%{public}s, serviceId=%{public}" PRId64 ", ret=%{public}d",
            pkgName.c_str(), serviceId, ret);
    }
    return ret;
}

int32_t DmServiceAdapter::GetTrustServiceInfo(const std::string &pkgName,
    const std::map<std::string, std::string> &param,
    std::vector<DistributedHardware::DmServiceInfo> &serviceInfo)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustServiceInfo(pkgName, param, serviceInfo);
    if (ret != 0) {
        HILOG_ERROR("GetTrustServiceInfo failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

int32_t DmServiceAdapter::GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
    std::vector<DistributedHardware::DmDeviceInfo> &deviceList)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetTrustedDeviceList(pkgName, extra, deviceList);
    if (ret != 0) {
        HILOG_ERROR("GetTrustedDeviceList failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

int32_t DmServiceAdapter::GetLocalDeviceNetworkId(const std::string &pkgName, std::string &networkId)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceNetWorkId(pkgName, networkId);
    if (ret != 0) {
        HILOG_ERROR("GetLocalDeviceNetworkId failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

int32_t DmServiceAdapter::GetLocalDeviceName(const std::string &pkgName, std::string &deviceName)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetLocalDeviceName(pkgName, deviceName);
    if (ret != 0) {
        HILOG_ERROR("GetLocalDeviceName failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

int32_t DmServiceAdapter::GetUdidByNetworkId(const std::string &pkgName, const std::string &networkId,
    std::string &udid)
{
    int32_t ret = DistributedHardware::DeviceManager::GetInstance().GetUdidByNetworkId(pkgName, networkId, udid);
    if (ret != 0) {
        HILOG_ERROR("GetUdidByNetworkId failed, pkgName=%{public}s, ret=%{public}d", pkgName.c_str(), ret);
    }
    return ret;
}

} // namespace AppExecFwk
} // namespace OHOS
