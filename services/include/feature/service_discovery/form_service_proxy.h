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

#ifndef OHOS_FORM_FWK_FORM_SERVICE_PROXY_H
#define OHOS_FORM_FWK_FORM_SERVICE_PROXY_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "feature/cross_device_publish/dm_service_adapter.h"
#include "form_service_info.h"

namespace OHOS {
namespace AppExecFwk {

// Register: validates → DM RegisterServiceInfo → DM StartPublishService → hooks.onStartListen
// Unregister: validates ownership → hooks.onStopListen → DM StopPublishService → DM UnRegisterServiceInfo
// SoftBus listen/stop-listen injected via ServiceTransportHooks (empty hooks = skip listen).
struct ServiceTransportHooks {
    std::function<ErrCode(int64_t serviceId)> onStartListen; // must return ERR_OK or error
    std::function<void(int64_t serviceId)> onStopListen;
};

class FormServiceProxy {
public:
    explicit FormServiceProxy(std::shared_ptr<IDmServiceAdapter> dmAdapter,
        ServiceTransportHooks hooks = {});
    ~FormServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(FormServiceProxy);

    ErrCode Register(const FormHostServiceInfo &info, int64_t &serviceId);
    ErrCode Unregister(int64_t serviceId);
    bool GetUserIdByServiceId(int64_t serviceId, int32_t &userId);
    void Dump(std::string &result);

private:
    ErrCode ResolveCallerIdentity(int32_t &userId, std::string &ownerPkgName);
    ErrCode ValidateInput(const FormHostServiceInfo &info);
    static std::string BuildServiceKey(const std::string &ownerPkgName, int32_t userId);
    DistributedHardware::DmRegisterServiceInfo BuildRegisterInfo(
        const FormHostServiceInfo &info, int32_t userId, const std::string &ownerPkgName);
    ErrCode RegisterWithDm(const DistributedHardware::DmRegisterServiceInfo &regInfo, int64_t &serviceId);

    struct LocalEntry {
        int64_t serviceId = -1;
        FormHostServiceInfo info;
    };

    std::shared_ptr<IDmServiceAdapter> dmAdapter_;
    ServiceTransportHooks hooks_;
    std::mutex mutex_;
    std::map<std::string, LocalEntry> localEntries_;      // key = ownerPkgName|userId
    std::map<int64_t, std::string> serviceIdToKey_;        // serviceId → serviceKey
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SERVICE_PROXY_H
