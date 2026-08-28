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

#include "feature/service_discovery/form_service_proxy.h"

#include <cinttypes>

#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "device_manager_callback.h"
#include "form_cross_device_constants.h"
#include "form_mgr_errors.h"
#include "form_service_constants.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
class FormServicePublishCallback : public DistributedHardware::ServicePublishCallback {
public:
    void OnServicePublishResult(int64_t serviceId, int32_t reason) override
    {
        HILOG_INFO("OnServicePublishResult: serviceId=%{public}" PRId64 ", reason=%{public}d", serviceId, reason);
    }
};
} // namespace

FormServiceProxy::FormServiceProxy(std::shared_ptr<IDmServiceAdapter> dmAdapter,
    ServiceTransportHooks hooks)
    : dmAdapter_(std::move(dmAdapter)), hooks_(std::move(hooks))
{}

ErrCode FormServiceProxy::Register(const FormHostServiceInfo &info, int64_t &serviceId)
{
    HILOG_DEBUG("serviceName:%{public}s", info.serviceName.c_str());
    ErrCode validRet = ValidateInput(info);
    if (validRet != ERR_OK) {
        return validRet;
    }

    int32_t userId = -1;
    std::string ownerPkgName;
    ErrCode idRet = ResolveCallerIdentity(userId, ownerPkgName);
    if (idRet != ERR_OK) {
        return idRet;
    }

    std::string serviceKey = BuildServiceKey(ownerPkgName, userId);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = localEntries_.find(serviceKey);
        if (it != localEntries_.end()) {
            serviceId = it->second.serviceId;
            HILOG_INFO("already registered: serviceId=%{public}" PRId64 " owner=%{public}s userId=%{public}d",
                serviceId, ownerPkgName.c_str(), userId);
            return ERR_OK;
        }
    }

    auto regInfo = BuildRegisterInfo(info, userId, ownerPkgName);
    ErrCode dmRet = RegisterWithDm(regInfo, serviceId);
    if (dmRet != ERR_OK) {
        return dmRet;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        LocalEntry entry;
        entry.serviceId = serviceId;
        entry.info = info;
        entry.info.ownerPkgName = ownerPkgName;
        entry.info.userId = userId;
        localEntries_[serviceKey] = std::move(entry);
        serviceIdToKey_[serviceId] = serviceKey;
    }

    HILOG_INFO("registered: serviceId=%{public}" PRId64 " owner=%{public}s userId=%{public}d",
        serviceId, ownerPkgName.c_str(), userId);
    return ERR_OK;
}

DistributedHardware::DmRegisterServiceInfo FormServiceProxy::BuildRegisterInfo(
    const FormHostServiceInfo &info, int32_t userId, const std::string &ownerPkgName)
{
    DistributedHardware::DmRegisterServiceInfo regInfo;
    regInfo.userId = userId;
    if (!FormUtil::ConvertStringToInt64(info.displayId, regInfo.displayId)) {
        HILOG_WARN("Invalid displayId format: %{public}s", info.displayId.c_str());
        regInfo.displayId = FORM_CD_DEFAULT_DISPLAY_ID;
    }
    regInfo.serviceOwnerTokenId = IPCSkeleton::GetCallingTokenID();
    regInfo.serviceOwnerPkgName = ownerPkgName;
    regInfo.serviceRegisterTokenId = IPCSkeleton::GetSelfTokenID();
    regInfo.serviceType = FORM_CD_SERVICE_TYPE;
    regInfo.serviceName = info.serviceName;
    regInfo.serviceDisplayName = info.serviceDisplayName;
    regInfo.customData = info.customData.empty() ? "{}" : info.customData;
    regInfo.dataLen = static_cast<uint32_t>(regInfo.customData.size());
    regInfo.timeStamp = FormUtil::GetCurrentMillisecond();
    regInfo.description = info.serviceDisplayName;
    regInfo.serviceCode = info.serviceName;

    HILOG_DEBUG("RegisterServiceInfo: owner=%{public}s, serviceName=%{public}s, userId=%{public}d",
        regInfo.serviceOwnerPkgName.c_str(), regInfo.serviceName.c_str(), regInfo.userId);
    return regInfo;
}

ErrCode FormServiceProxy::RegisterWithDm(
    const DistributedHardware::DmRegisterServiceInfo &regInfo, int64_t &serviceId)
{
    serviceId = -1;
    int32_t dmRet = dmAdapter_->RegisterServiceInfo(regInfo, serviceId);
    if (dmRet != 0) {
        HILOG_ERROR("RegisterServiceInfo failed, ret=%{public}d", dmRet);
        return ERR_APPEXECFWK_FORM_SERVICE_PUBLISH_FAILED;
    }
    HILOG_INFO("RegisterServiceInfo succeeded, serviceId=%{public}" PRId64, serviceId);

    DistributedHardware::DmPublishServiceParam publishParam;
    publishParam.discoverMode = DistributedHardware::DMSrvDiscoveryMode::SERVICE_PUBLISH_MODE_PASSIVE;
    publishParam.media = DistributedHardware::DMSrvMediumType::SERVICE_MEDIUM_TYPE_AUTO;
    publishParam.freq = DistributedHardware::DmExchangeFreq::DM_LOW;

    auto callback = std::make_shared<FormServicePublishCallback>();
    dmRet = dmAdapter_->StartPublishService(FORM_SERVICE_OWNER_PKG, serviceId, publishParam, callback);
    if (dmRet != 0) {
        HILOG_ERROR("StartPublishService failed, serviceId=%{public}" PRId64 ", ret=%{public}d",
            serviceId, dmRet);
        dmAdapter_->UnRegisterServiceInfo(serviceId);
        return ERR_APPEXECFWK_FORM_SERVICE_PUBLISH_FAILED;
    }

    if (hooks_.onStartListen) {
        ErrCode listenRet = hooks_.onStartListen(serviceId);
        if (listenRet != ERR_OK) {
            HILOG_ERROR("StartListen failed, serviceId=%{public}" PRId64 ", rolling back DM registration",
                serviceId);
            dmAdapter_->StopPublishService(FORM_SERVICE_OWNER_PKG, serviceId);
            dmAdapter_->UnRegisterServiceInfo(serviceId);
            return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
        }
    }
    return ERR_OK;
}

ErrCode FormServiceProxy::Unregister(int64_t serviceId)
{
    int32_t userId = -1;
    std::string ownerPkgName;
    ErrCode idRet = ResolveCallerIdentity(userId, ownerPkgName);
    if (idRet != ERR_OK) {
        return idRet;
    }

    std::string serviceKey = BuildServiceKey(ownerPkgName, userId);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = localEntries_.find(serviceKey);
        if (it == localEntries_.end()) {
            HILOG_ERROR("service not found in local index: owner=%{public}s userId=%{public}d",
                ownerPkgName.c_str(), userId);
            return ERR_APPEXECFWK_FORM_SERVICE_NOT_EXIST;
        }
        if (it->second.serviceId != serviceId) {
            HILOG_ERROR("serviceId mismatch: caller owns serviceId=%{public}" PRId64
                " but requested serviceId=%{public}" PRId64,
                it->second.serviceId, serviceId);
            return ERR_APPEXECFWK_FORM_SERVICE_NOT_SELF;
        }
    }

    if (hooks_.onStopListen) {
        hooks_.onStopListen(serviceId);
    }

    int32_t dmRet = dmAdapter_->StopPublishService(FORM_SERVICE_OWNER_PKG, serviceId);
    if (dmRet != 0) {
        HILOG_WARN("StopPublishService failed, serviceId=%{public}" PRId64 ", ret=%{public}d", serviceId, dmRet);
    }

    dmRet = dmAdapter_->UnRegisterServiceInfo(serviceId);
    if (dmRet != 0) {
        HILOG_WARN("UnRegisterServiceInfo failed, serviceId=%{public}" PRId64 ", ret=%{public}d", serviceId, dmRet);
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        localEntries_.erase(serviceKey);
        serviceIdToKey_.erase(serviceId);
    }

    HILOG_INFO("unregistered: serviceId=%{public}" PRId64 " owner=%{public}s userId=%{public}d",
        serviceId, ownerPkgName.c_str(), userId);
    return ERR_OK;
}

bool FormServiceProxy::GetUserIdByServiceId(int64_t serviceId, int32_t &userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = serviceIdToKey_.find(serviceId);
    if (it == serviceIdToKey_.end()) {
        return false;
    }
    auto entryIt = localEntries_.find(it->second);
    if (entryIt != localEntries_.end()) {
        userId = entryIt->second.info.userId;
        return true;
    }
    return false;
}

void FormServiceProxy::Dump(std::string &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    result += "  registered: " + std::to_string(localEntries_.size()) + "\n";
    int32_t index = 0;
    for (const auto &item : localEntries_) {
        result += "    [" + std::to_string(index++) + "] serviceId=" + std::to_string(item.second.serviceId) +
            " owner=" + item.second.info.ownerPkgName +
            " serviceName=" + item.second.info.serviceName + "\n";
    }
}

ErrCode FormServiceProxy::ResolveCallerIdentity(int32_t &userId, std::string &ownerPkgName)
{
    userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    if (FormBmsHelper::GetInstance().GetCallerBundleName(ownerPkgName) != ERR_OK || ownerPkgName.empty()) {
        HILOG_ERROR("get caller bundleName failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode FormServiceProxy::ValidateInput(const FormHostServiceInfo &info)
{
    if (info.serviceName.empty() ||
        info.serviceName.size() > static_cast<size_t>(FORM_SERVICE_MAX_SERVICE_NAME)) {
        HILOG_ERROR("serviceName invalid, size:%{public}d", static_cast<int32_t>(info.serviceName.size()));
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (info.serviceDisplayName.size() < static_cast<size_t>(FORM_SERVICE_MIN_DISPLAYNAME) ||
        info.serviceDisplayName.size() > static_cast<size_t>(FORM_SERVICE_MAX_DISPLAYNAME)) {
        HILOG_ERROR("serviceDisplayName invalid, size:%{public}d",
            static_cast<int32_t>(info.serviceDisplayName.size()));
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}

std::string FormServiceProxy::BuildServiceKey(const std::string &ownerPkgName, int32_t userId)
{
    return ownerPkgName + "|" + std::to_string(userId);
}

} // namespace AppExecFwk
} // namespace OHOS
