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

#ifndef OHOS_FORM_FWK_FORM_PUBLISH_ROUTER_H
#define OHOS_FORM_FWK_FORM_PUBLISH_ROUTER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "feature/service_gateway/form_frame_handler.h"
#include "feature/service_gateway/form_connection_pool.h"
#include "feature/service_discovery/form_service_proxy.h"
#include "form_cross_device_request.h"
#include "iremote_object.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
class IFormCrossDevicePublishCallback;

// Coordinates FormServiceProxy (access control) and FormConnectionPool (transport).
// Only handles REQUEST_PUBLISH frames on the server side.
class FormPublishRouter final : public IFrameHandler,
    public DelayedRefSingleton<FormPublishRouter> {
    DECLARE_DELAYED_REF_SINGLETON(FormPublishRouter)

public:
    DISALLOW_COPY_AND_MOVE(FormPublishRouter);

    void Init();

    ErrCode RequestPublish(const FormCrossDeviceRequest &request,
        const sptr<IRemoteObject> &callerToken, const sptr<IRemoteObject> &callback);

    ErrCode HandleIncomingPublish(const FormCrossDeviceRequest &req, PublishFormCrossDeviceResult &res);

    ErrCode StartListen(int64_t serviceId);
    void StopListen(int64_t serviceId);
    std::shared_ptr<FormServiceProxy> GetServiceProxy();

    void Dump(std::string &result);

private:
    void EnsureMembers();

    // IFrameHandler
    void OnFrame(int32_t fd, FormCdMsgType msgType,
        uint32_t seqId, const std::string &payload) override;

    void SendResponseFrame(int32_t fd, const std::string &frame);
    void SendErrorFrame(int32_t fd, uint32_t seqId, ErrCode errCode);

    void CancelPendingTimer(uint32_t seqId);

    ErrCode ValidatePublishParams(const FormCrossDeviceRequest &request,
        const sptr<IRemoteObject> &callback, sptr<IFormCrossDevicePublishCallback> &outCb);
    ErrCode EnsurePeerConnection(const std::string &peerNetworkId, int64_t peerServiceId);
    void RegisterPublishResponseHandler(uint32_t seqId, const std::string &peerNetworkId,
        const sptr<IFormCrossDevicePublishCallback> &cb);
    ErrCode SendPublishFrame(const FormCrossDeviceRequest &request, uint32_t seqId);
    void StartPublishTimer(uint32_t seqId, const sptr<IFormCrossDevicePublishCallback> &cb);

    std::shared_ptr<FormServiceProxy> serviceProxy_;
    std::shared_ptr<FormConnectionPool> connectionPool_;
    std::once_flag initOnce_;
    std::atomic<uint32_t> seqGen_{0};
    std::mutex timerMutex_;
    std::unordered_map<uint32_t, int32_t> pendingTimers_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_PUBLISH_ROUTER_H
