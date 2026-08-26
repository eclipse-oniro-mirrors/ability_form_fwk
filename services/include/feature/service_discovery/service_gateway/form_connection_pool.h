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

#ifndef OHOS_FORM_FWK_FORM_CONNECTION_POOL_H
#define OHOS_FORM_FWK_FORM_CONNECTION_POOL_H

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "device_manager_callback.h"
#include "feature/cross_device_publish/form_cross_device_codec.h"
#include "feature/cross_device_publish/form_softbus_session_registry.h"
#include "feature/service_gateway/form_frame_handler.h"
#include "form_cross_device_constants.h"
#include "form_cross_device_request.h"
#include "form_service_constants.h"
#include "trans_type.h"
#include "dm_device_info.h"

namespace OHOS {
namespace AppExecFwk {
// One persistent connection per peerNetworkId; service-level demux via peerServiceId in payload.
// State machine: IDLE → BINDING → READY → (FAILED → retry or IDLE)
class FormConnectionPool : public ISocketSession,
                           public std::enable_shared_from_this<FormConnectionPool> {
public:
    using ResponseHandler = std::function<void(FormCdMsgType, uint32_t, const std::string &)>;

    FormConnectionPool() = default;
    ~FormConnectionPool() override;

    DISALLOW_COPY_AND_MOVE(FormConnectionPool);

    ErrCode StartListen(int64_t serviceId);  // idempotent per serviceId
    void StopListen(int64_t serviceId);

    ErrCode GetOrCreateConnection(const std::string &peerNetworkId, int64_t peerServiceId = 0,
        bool forceReconnect = false);

    ErrCode SendFrame(const std::string &peerNetworkId, FormCdMsgType msgType,
        uint32_t seqId, const std::string &payload);
    ErrCode SendRawFrame(const std::string &peerNetworkId, const std::string &frame);
    ErrCode SendRawFrameByFd(int32_t fd, const std::string &frame);

    void RegisterResponseHandler(uint32_t seqId, const std::string &peerNetworkId, ResponseHandler handler);
    void UnregisterResponseHandler(uint32_t seqId);
    void CloseConnection(const std::string &peerNetworkId);
    void SetFrameHandler(IFrameHandler *handler);

    // ISocketSession
    void OnServiceBind(int32_t fd, ServiceSocketInfo info) override;
    bool OnServiceNegotiate(int32_t fd, ServiceSocketInfo info) override;
    void OnBytes(int32_t fd, const void *data, uint32_t len) override;
    void OnShutdown(int32_t fd, ShutdownReason reason) override;
    void OnError(int32_t fd, int32_t errCode) override;

    void Dump(std::string &result);

private:
    enum class ConnState { IDLE, BINDING, READY, FAILED };
    enum class ExistingConnResult { READY, NEED_CREATE, BIND_TIMEOUT };

    struct PeerConnection {
        std::string peerNetworkId;
        std::string peerUuid;
        int64_t peerServiceId = 0;
        int32_t fd = -1;
        ConnState state = ConnState::IDLE;
        int64_t lastActiveTime = 0;
        int32_t retryCount = 0;
        std::condition_variable cv;
    };

    ExistingConnResult WaitForExistingConnection(const std::string &peerNetworkId);
    ErrCode CreateAndBindConnection(const std::string &peerNetworkId, int64_t peerServiceId);
    ErrCode ResolvePeerUuid(const std::string &peerNetworkId, std::string &peerUuid);
    int32_t CreateClientSocket(const std::string &peerUuid, int64_t peerServiceId);
    void RegisterConnEntry(const std::string &peerNetworkId, const std::string &peerUuid,
        int64_t peerServiceId, int32_t fd);
    ErrCode SyncBindToPeer(const std::string &peerNetworkId, int32_t fd);
    ErrCode StartAsyncBind(const std::string &peerNetworkId, int32_t fd);
    void RollbackAsyncBind(const std::string &peerNetworkId, int32_t fd);
    ErrCode BindToPeer(const std::string &peerNetworkId, const std::string &peerUuid, int64_t peerServiceId);
    void MarkConnFailed(const std::string &peerNetworkId);
    void HandleSendFailure(const std::string &peerNetworkId);
    void EvictLruIfNeeded();
    void ScheduleReconnect(const std::string &peerNetworkId);
    FormCrossDeviceCodec codec_;
    IFrameHandler *frameHandler_ = nullptr;
    std::mutex mutex_;
    std::map<int64_t, int32_t> listenFds_;
    bool serverRegistered_ = false;
    std::map<std::string, PeerConnection> connections_;
    std::map<int32_t, std::string> fdToPeer_;
    std::map<uint32_t, ResponseHandler> pendingHandlers_;
    std::map<uint32_t, std::string> seqToPeer_;
    std::atomic<uint32_t> seqGen_{0};
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CONNECTION_POOL_H
