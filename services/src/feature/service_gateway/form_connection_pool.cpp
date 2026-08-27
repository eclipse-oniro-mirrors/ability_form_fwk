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

#include "feature/service_gateway/form_connection_pool.h"

#include <cinttypes>
#include <chrono>
#include <cstring>

#include "device_manager.h"
#include "dm_device_info.h"
#include "form_cross_device_constants.h"
#include "form_mgr_errors.h"
#include "form_service_constants.h"
#include "fms_log_wrapper.h"
#include "hitrace_meter.h"
#include "socket.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::DistributedHardware;

namespace {
int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

bool CopyNetworkIdBuf(const std::string &peerUuid, char (&buf)[DEVICE_ID_LEN_MAX])
{
    if (peerUuid.size() >= DEVICE_ID_LEN_MAX) {
        HILOG_ERROR("peerUuid too long: %{public}zu", peerUuid.size());
        return false;
    }
    errno_t ret = strcpy_s(buf, sizeof(buf), peerUuid.c_str());
    if (ret != EOK) {
        HILOG_ERROR("strcpy_s failed for peerUuid");
        return false;
    }
    return true;
}

constexpr size_t QOS_TV_COUNT = 3;

void FillSyncBindQos(QosTV qos[])
{
    qos[0] = { .qos = QOS_TYPE_MIN_BW, .value = FORM_CD_QOS_MIN_BW };
    qos[1] = { .qos = QOS_TYPE_MAX_WAIT_TIMEOUT, .value = FORM_CD_QOS_MAX_WAIT_TIMEOUT_MS };
    qos[2] = { .qos = QOS_TYPE_MIN_LATENCY, .value = FORM_CD_QOS_MIN_LATENCY_MS };
}

void FillAsyncBindQos(QosTV qos[])
{
    qos[0] = { .qos = QOS_TYPE_MIN_BW, .value = FORM_CD_QOS_MIN_BW };
    qos[1] = { .qos = QOS_TYPE_MAX_LATENCY, .value = FORM_CD_QOS_MAX_LATENCY_MS };
    qos[2] = { .qos = QOS_TYPE_MIN_LATENCY, .value = FORM_CD_QOS_MIN_LATENCY_MS };
}
} // namespace

FormConnectionPool::~FormConnectionPool()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &item : connections_) {
            if (item.second.fd >= 0) {
                FormSoftbusSessionRegistry::Instance().UnregisterClient(item.second.fd);
                Shutdown(item.second.fd);
            }
        }
        connections_.clear();
        fdToPeer_.clear();
        for (auto &item : listenFds_) {
            Shutdown(item.second);
        }
        listenFds_.clear();
    }
    FormSoftbusSessionRegistry::Instance().UnregisterServer();
}

void FormConnectionPool::SetFrameHandler(IFrameHandler *handler)
{
    frameHandler_ = handler;
}

ErrCode FormConnectionPool::StartListen(int64_t serviceId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (listenFds_.count(serviceId) > 0) {
            HILOG_INFO("already listening on serviceId=%{public}" PRId64, serviceId);
            return ERR_OK;
        }
    }

    char networkId[] = "";
    ServiceSocketInfo info = {
        .peerNetworkId = networkId,
        .serviceId = serviceId,
        .dataType = DATA_TYPE_BYTES,
    };
    int32_t fd = ServiceSocket(info);
    if (fd < 0) {
        HILOG_ERROR("ServiceSocket failed for serviceId=%{public}" PRId64 " ret=%{public}d", serviceId, fd);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }

    QosTV qos[QOS_TV_COUNT];
    FillAsyncBindQos(qos);
    int32_t ret = Listen(fd, qos, QOS_TV_COUNT, &FormSoftbusSessionRegistry::Listener());
    if (ret != 0) {
        HILOG_ERROR("Listen failed for serviceId=%{public}" PRId64 " ret=%{public}d", serviceId, ret);
        Shutdown(fd);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        listenFds_[serviceId] = fd;
        if (!serverRegistered_) {
            FormSoftbusSessionRegistry::Instance().RegisterServer(shared_from_this());
            serverRegistered_ = true;
        }
    }
    HILOG_INFO("StartListen succeeded, serviceId=%{public}" PRId64 " listenFd=%{public}d", serviceId, fd);
    return ERR_OK;
}

void FormConnectionPool::StopListen(int64_t serviceId)
{
    int32_t fd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = listenFds_.find(serviceId);
        if (it != listenFds_.end()) {
            fd = it->second;
            listenFds_.erase(it);
        }
    }
    if (fd >= 0) {
        Shutdown(fd);
        HILOG_INFO("StopListen: serviceId=%{public}" PRId64 " listenFd=%{public}d", serviceId, fd);
    }
}

ErrCode FormConnectionPool::GetOrCreateConnection(const std::string &peerNetworkId, int64_t peerServiceId,
    bool forceReconnect)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("connect peer:%{public}s, peerServiceId:%{public}" PRId64
        " forceReconnect=%{public}d",
        peerNetworkId.c_str(), peerServiceId, static_cast<int32_t>(forceReconnect));
    if (peerNetworkId.empty()) {
        return ERR_APPEXECFWK_FORM_CD_INVALID_PARAM;
    }

    if (forceReconnect) {
        CloseConnection(peerNetworkId);
    }

    auto existing = WaitForExistingConnection(peerNetworkId);
    if (existing == ExistingConnResult::READY) {
        return ERR_OK;
    }
    if (existing == ExistingConnResult::BIND_TIMEOUT) {
        return ERR_APPEXECFWK_FORM_CD_BIND_TIMEOUT;
    }
    return CreateAndBindConnection(peerNetworkId, peerServiceId);
}

FormConnectionPool::ExistingConnResult FormConnectionPool::WaitForExistingConnection(const std::string &peerNetworkId)
{
    std::unique_lock<std::mutex> lock(mutex_);
    auto it = connections_.find(peerNetworkId);
    if (it == connections_.end()) {
        return ExistingConnResult::NEED_CREATE;
    }

    if (it->second.state == ConnState::READY) {
        HILOG_INFO("reusing existing READY connection for peer:%{public}s", peerNetworkId.c_str());
        return ExistingConnResult::READY;
    }

    if (it->second.state == ConnState::BINDING) {
        int64_t waitStart = NowMs();
        auto &conn = it->second;
        conn.cv.wait_for(lock, std::chrono::milliseconds(FORM_CD_BIND_WAIT_TIMEOUT_MS),
            [&conn]() { return conn.state != ConnState::BINDING; });
        int64_t waitElapsed = NowMs() - waitStart;
        if (conn.state == ConnState::READY) {
            HILOG_INFO("BINDING->READY after %{public}" PRId64 "ms for peer:%{public}s",
                waitElapsed, peerNetworkId.c_str());
            return ExistingConnResult::READY;
        }
        HILOG_WARN("BINDING wait timed out after %{public}" PRId64 "ms for peer:%{public}s",
            waitElapsed, peerNetworkId.c_str());
        return ExistingConnResult::BIND_TIMEOUT;
    }

    // IDLE or FAILED — clean up stale entry so a fresh connection can be created
    HILOG_INFO("existing connection in state=%{public}d, recreating for peer:%{public}s",
        static_cast<int32_t>(it->second.state), peerNetworkId.c_str());
    int32_t staleFd = it->second.fd;
    fdToPeer_.erase(staleFd);
    it->second.fd = -1;
    connections_.erase(it);
    if (staleFd >= 0) {
        FormSoftbusSessionRegistry::Instance().UnregisterClient(staleFd);
        Shutdown(staleFd);
    }
    return ExistingConnResult::NEED_CREATE;
}

ErrCode FormConnectionPool::CreateAndBindConnection(const std::string &peerNetworkId, int64_t peerServiceId)
{
    EvictLruIfNeeded();

    std::string peerUuid;
    ErrCode err = ResolvePeerUuid(peerNetworkId, peerUuid);
    if (err != ERR_OK) {
        return err;
    }

    int32_t fd = CreateClientSocket(peerUuid, peerServiceId);
    if (fd < 0) {
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }

    RegisterConnEntry(peerNetworkId, peerUuid, peerServiceId, fd);
    FormSoftbusSessionRegistry::Instance().RegisterClient(fd, shared_from_this());

    return SyncBindToPeer(peerNetworkId, fd);
}

ErrCode FormConnectionPool::ResolvePeerUuid(const std::string &peerNetworkId, std::string &peerUuid)
{
    int32_t dmRet = DeviceManager::GetInstance().GetUuidByNetworkId(
        FORM_SERVICE_OWNER_PKG, peerNetworkId, peerUuid);
    if (dmRet != 0 || peerUuid.empty()) {
        HILOG_ERROR("GetUuidByNetworkId failed for peer:%{public}s ret=%{public}d", peerNetworkId.c_str(), dmRet);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }
    return ERR_OK;
}

int32_t FormConnectionPool::CreateClientSocket(const std::string &peerUuid, int64_t peerServiceId)
{
    char networkIdBuf[DEVICE_ID_LEN_MAX] = {0};
    if (!CopyNetworkIdBuf(peerUuid, networkIdBuf)) {
        return -1;
    }
    ServiceSocketInfo info = {
        .peerNetworkId = networkIdBuf,
        .serviceId = 0,
        .peerServiceId = peerServiceId,
        .dataType = DATA_TYPE_BYTES,
    };
    int32_t fd = ServiceSocket(info);
    if (fd < 0) {
        HILOG_ERROR("ServiceSocket failed for peerUuid:%{public}s ret=%{public}d", peerUuid.c_str(), fd);
    }
    return fd;
}

void FormConnectionPool::RegisterConnEntry(const std::string &peerNetworkId, const std::string &peerUuid,
    int64_t peerServiceId, int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    PeerConnection &conn = connections_[peerNetworkId];
    conn.peerNetworkId = peerNetworkId;
    conn.peerUuid = peerUuid;
    conn.peerServiceId = peerServiceId;
    conn.fd = fd;
    conn.state = ConnState::BINDING;
    conn.lastActiveTime = NowMs();
    conn.retryCount = 0;
    fdToPeer_[fd] = peerNetworkId;
}

ErrCode FormConnectionPool::SyncBindToPeer(const std::string &peerNetworkId, int32_t fd)
{
    QosTV qos[QOS_TV_COUNT];
    FillSyncBindQos(qos);
    int64_t bindStart = NowMs();
    int32_t ret = Bind(fd, qos, QOS_TV_COUNT, &FormSoftbusSessionRegistry::Listener());
    int64_t bindElapsed = NowMs() - bindStart;

    if (ret != 0) {
        HILOG_ERROR("Bind failed for peer:%{public}s ret=%{public}d after %{public}" PRId64 "ms",
            peerNetworkId.c_str(), ret, bindElapsed);
        std::lock_guard<std::mutex> lock(mutex_);
        FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
        Shutdown(fd);
        connections_.erase(peerNetworkId);
        fdToPeer_.erase(fd);
        return ERR_APPEXECFWK_FORM_CD_BIND_TIMEOUT;
    }

    HILOG_INFO("Bind succeeded for peer:%{public}s fd=%{public}d elapsed=%{public}" PRId64 "ms",
        peerNetworkId.c_str(), fd, bindElapsed);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it != connections_.end()) {
            it->second.state = ConnState::READY;
            it->second.lastActiveTime = NowMs();
            it->second.cv.notify_all();
        }
    }
    return ERR_OK;
}

ErrCode FormConnectionPool::SendFrame(const std::string &peerNetworkId, FormCdMsgType msgType,
    uint32_t seqId, const std::string &payload)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string frame;
    int32_t fd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it == connections_.end() || it->second.state != ConnState::READY) {
            HILOG_ERROR("connection not ready for peer:%{public}s", peerNetworkId.c_str());
            return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
        }
        if (static_cast<uint8_t>(msgType) < FORM_CD_MSG_RESPONSE_BASE) {
            if (!FormCrossDeviceCodec::BuildRawFrame(msgType, seqId, payload, frame)) {
                HILOG_ERROR("BuildRawFrame failed");
                return ERR_APPEXECFWK_FORM_CD_CODEC_FAILED;
            }
        } else {
            frame = payload;
        }
        fd = it->second.fd;
    } // release lock before SendBytes — avoid holding mutex during blocking I/O

    int32_t ret = SendBytes(fd, frame.data(), static_cast<uint32_t>(frame.size()));
    if (ret != 0) {
        HILOG_ERROR("SendBytes failed fd=%{public}d ret=%{public}d", fd, ret);
        HandleSendFailure(peerNetworkId);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it != connections_.end()) {
            it->second.lastActiveTime = NowMs();
        }
    }
    return ERR_OK;
}

ErrCode FormConnectionPool::SendRawFrame(const std::string &peerNetworkId, const std::string &frame)
{
    int32_t fd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it == connections_.end() || it->second.state != ConnState::READY) {
            HILOG_ERROR("connection not ready for peer:%{public}s", peerNetworkId.c_str());
            return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
        }
        fd = it->second.fd;
    }

    int32_t ret = SendBytes(fd, frame.data(), static_cast<uint32_t>(frame.size()));
    if (ret != 0) {
        HILOG_ERROR("SendBytes failed fd=%{public}d ret=%{public}d", fd, ret);
        HandleSendFailure(peerNetworkId);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it != connections_.end()) {
            it->second.lastActiveTime = NowMs();
        }
    }
    return ERR_OK;
}

ErrCode FormConnectionPool::SendRawFrameByFd(int32_t fd, const std::string &frame)
{
    int32_t ret = SendBytes(fd, frame.data(), static_cast<uint32_t>(frame.size()));
    if (ret != 0) {
        HILOG_ERROR("SendBytes failed fd=%{public}d ret=%{public}d size=%{public}zu",
            fd, ret, frame.size());
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }
    HILOG_DEBUG("SendBytes ok fd=%{public}d size=%{public}zu", fd, frame.size());
    return ERR_OK;
}

void FormConnectionPool::RegisterResponseHandler(uint32_t seqId, const std::string &peerNetworkId,
    ResponseHandler handler)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pendingHandlers_[seqId] = std::move(handler);
    seqToPeer_[seqId] = peerNetworkId;
}

void FormConnectionPool::UnregisterResponseHandler(uint32_t seqId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pendingHandlers_.erase(seqId);
    seqToPeer_.erase(seqId);
}

void FormConnectionPool::CloseConnection(const std::string &peerNetworkId)
{
    int32_t fd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it != connections_.end()) {
            fd = it->second.fd;
            FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
            connections_.erase(it);
            fdToPeer_.erase(fd);
        }
    }
    if (fd >= 0) {
        codec_.Clear(fd);
        Shutdown(fd);
    }
}

void FormConnectionPool::OnServiceBind(int32_t fd, ServiceSocketInfo info)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = fdToPeer_.find(fd);
        if (it != fdToPeer_.end()) {
            const std::string &peerNetworkId = it->second;
            auto connIt = connections_.find(peerNetworkId);
            if (connIt != connections_.end()) {
                connIt->second.state = ConnState::READY;
                connIt->second.lastActiveTime = NowMs();
                connIt->second.cv.notify_all();
                HILOG_INFO("peer connected: networkId=%{public}s fd=%{public}d", peerNetworkId.c_str(), fd);
            }
        } else {
            // Incoming connection (server-side accept)
            HILOG_INFO("incoming connection accepted: fd=%{public}d", fd);
        }
    }
}

bool FormConnectionPool::OnServiceNegotiate(int32_t fd, ServiceSocketInfo info)
{
    HILOG_INFO("negotiate accept: fd=%{public}d", fd);
    return true;
}

void FormConnectionPool::OnBytes(int32_t fd, const void *data, uint32_t len)
{
    HILOG_DEBUG("OnBytes: fd=%{public}d len=%{public}u", fd, len);
    codec_.Feed(fd, data, len, [this, fd](FormCdMsgType msgType, uint32_t seqId, const std::string &payload) {
        HILOG_INFO("frame decoded: fd=%{public}d msgType=%{public}u seq=%{public}u payloadLen=%{public}zu",
            fd, static_cast<uint32_t>(msgType), seqId, payload.size());
        // Client-side: match pending request response
        ResponseHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = pendingHandlers_.find(seqId);
            if (it != pendingHandlers_.end()) {
                handler = it->second;
                pendingHandlers_.erase(it);
                seqToPeer_.erase(seqId);
                HILOG_INFO("matched pending handler for seq=%{public}u, remaining=%{public}zu",
                    seqId, pendingHandlers_.size());
            }
        }
        if (handler) {
            handler(msgType, seqId, payload);
            return;
        }

        // Server-side: dispatch incoming frame to handler (Strategy pattern)
        if (frameHandler_ == nullptr) {
            HILOG_WARN("frameHandler is null, dropping incoming frame type=%{public}u seq=%{public}u",
                static_cast<uint32_t>(msgType), seqId);
            return;
        }
        HILOG_INFO("dispatching to frameHandler: fd=%{public}d msgType=%{public}u seq=%{public}u",
            fd, static_cast<uint32_t>(msgType), seqId);
        frameHandler_->OnFrame(fd, msgType, seqId, payload);
    });
}

void FormConnectionPool::OnShutdown(int32_t fd, ShutdownReason reason)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("OnShutdown: fd=%{public}d reason=%{public}d", fd, static_cast<int32_t>(reason));
    codec_.Clear(fd);

    std::string peerNetworkId;
    bool hasPending = false;
    size_t removedCount = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = fdToPeer_.find(fd);
        if (it != fdToPeer_.end()) {
            peerNetworkId = it->second;
            auto connIt = connections_.find(peerNetworkId);
            if (connIt != connections_.end()) {
                HILOG_INFO("connection closed: peer=%{public}s lastActive=%{public}" PRId64 "ms ago",
                    peerNetworkId.c_str(), NowMs() - connIt->second.lastActiveTime);
                connIt->second.fd = -1;
                connIt->second.state = ConnState::IDLE;
                connIt->second.cv.notify_all();
            }
            fdToPeer_.erase(it);
        }

        // Only remove handlers belonging to the disconnected peer
        std::vector<uint32_t> orphanedSeqIds;
        for (const auto &[sid, peer] : seqToPeer_) {
            if (peer == peerNetworkId) {
                orphanedSeqIds.push_back(sid);
            }
        }
        removedCount = orphanedSeqIds.size();
        if (removedCount > 0) {
            HILOG_WARN("clearing %{public}zu orphaned pending handlers on fd=%{public}d shutdown (peer=%{public}s)",
                removedCount, fd, peerNetworkId.c_str());
            for (uint32_t sid : orphanedSeqIds) {
                pendingHandlers_.erase(sid);
                seqToPeer_.erase(sid);
            }
        }
        hasPending = !orphanedSeqIds.empty();
    }

    if (!peerNetworkId.empty() && hasPending) {
        ScheduleReconnect(peerNetworkId);
    }
}

void FormConnectionPool::OnError(int32_t fd, int32_t errCode)
{
    HILOG_ERROR("fd=%{public}d errCode=%{public}d", fd, errCode);
    OnShutdown(fd, static_cast<ShutdownReason>(0));
}

ErrCode FormConnectionPool::BindToPeer(const std::string &peerNetworkId,
    const std::string &peerUuid, int64_t peerServiceId)
{
    int32_t fd = CreateClientSocket(peerUuid, peerServiceId);
    if (fd < 0) {
        MarkConnFailed(peerNetworkId);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }
    return StartAsyncBind(peerNetworkId, fd);
}

ErrCode FormConnectionPool::StartAsyncBind(const std::string &peerNetworkId, int32_t fd)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it == connections_.end()) {
            HILOG_WARN("connection removed during reconnect for peer:%{public}s", peerNetworkId.c_str());
            FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
            Shutdown(fd);
            return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
        }
        auto &conn = it->second;
        conn.fd = fd;
        conn.state = ConnState::BINDING;
        conn.lastActiveTime = NowMs();
        fdToPeer_[fd] = peerNetworkId;
    }

    FormSoftbusSessionRegistry::Instance().RegisterClient(fd, shared_from_this());

    QosTV qos[QOS_TV_COUNT];
    FillAsyncBindQos(qos);
    int32_t ret = BindAsync(fd, qos, QOS_TV_COUNT, &FormSoftbusSessionRegistry::Listener());
    if (ret != 0) {
        HILOG_ERROR("BindAsync failed for peer:%{public}s ret=%{public}d", peerNetworkId.c_str(), ret);
        RollbackAsyncBind(peerNetworkId, fd);
        return ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    }
    return ERR_OK;
}

void FormConnectionPool::RollbackAsyncBind(const std::string &peerNetworkId, int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
    Shutdown(fd);
    fdToPeer_.erase(fd);
    auto it = connections_.find(peerNetworkId);
    if (it != connections_.end()) {
        it->second.fd = -1;
        it->second.state = ConnState::FAILED;
    }
}

void FormConnectionPool::MarkConnFailed(const std::string &peerNetworkId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(peerNetworkId);
    if (it != connections_.end()) {
        it->second.fd = -1;
        it->second.state = ConnState::FAILED;
    }
}

void FormConnectionPool::HandleSendFailure(const std::string &peerNetworkId)
{
    int32_t fd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it == connections_.end() || it->second.state != ConnState::READY) {
            HILOG_INFO("connection already cleaned up for peer:%{public}s", peerNetworkId.c_str());
            return;
        }
        fd = it->second.fd;
        it->second.fd = -1;
        it->second.state = ConnState::IDLE;
        it->second.cv.notify_all();
        fdToPeer_.erase(fd);
        FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
    }
    if (fd >= 0) {
        codec_.Clear(fd);
        Shutdown(fd);
    }
    HILOG_INFO("SendBytes failure triggered reconnection for peer:%{public}s", peerNetworkId.c_str());
    ScheduleReconnect(peerNetworkId);
}

void FormConnectionPool::EvictLruIfNeeded()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (static_cast<int32_t>(connections_.size()) < FORM_CD_MAX_PEER_CONNECTIONS) {
        return;
    }

    int64_t oldestTime = INT64_MAX;
    std::string oldestPeer;
    for (const auto &item : connections_) {
        if ((item.second.state == ConnState::READY || item.second.state == ConnState::FAILED) &&
            item.second.lastActiveTime < oldestTime) {
            oldestTime = item.second.lastActiveTime;
            oldestPeer = item.first;
        }
    }

    if (!oldestPeer.empty()) {
        HILOG_INFO("evicting LRU connection peer:%{public}s", oldestPeer.c_str());
        auto it = connections_.find(oldestPeer);
        if (it != connections_.end()) {
            int32_t fd = it->second.fd;
            FormSoftbusSessionRegistry::Instance().UnregisterClient(fd);
            fdToPeer_.erase(fd);
            connections_.erase(it);
            if (fd >= 0) {
                codec_.Clear(fd);
                Shutdown(fd);
            }
        }
    }
}

void FormConnectionPool::ScheduleReconnect(const std::string &peerNetworkId)
{
    std::string peerUuid;
    int64_t peerServiceId = 0;
    int32_t retryCount = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = connections_.find(peerNetworkId);
        if (it == connections_.end()) {
            return;
        }
        auto &conn = it->second;
        if (conn.retryCount >= FORM_CD_MAX_RETRY_COUNT) {
            HILOG_WARN("max retry reached for peer:%{public}s, giving up", peerNetworkId.c_str());
            conn.state = ConnState::FAILED;
            return;
        }
        conn.retryCount++;
        retryCount = conn.retryCount;
        peerUuid = conn.peerUuid;
        peerServiceId = conn.peerServiceId;
    }
    // mutex_ released — safe to do blocking SoftBus/DM calls without risk of deadlock
    HILOG_INFO("reconnecting to peer:%{public}s attempt=%{public}d", peerNetworkId.c_str(), retryCount);
    BindToPeer(peerNetworkId, peerUuid, peerServiceId);
}

void FormConnectionPool::Dump(std::string &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    result += "== FormConnectionPool ==\n";
    result += "  listen sockets: " + std::to_string(listenFds_.size()) + "\n";
    for (const auto &item : listenFds_) {
        result += "    serviceId=" + std::to_string(item.first) +
            " listenFd=" + std::to_string(item.second) + "\n";
    }
    result += "  peer connections: " + std::to_string(connections_.size()) + "\n";
    for (const auto &item : connections_) {
        result += "    peer=" + item.first +
            " fd=" + std::to_string(item.second.fd) +
            " state=" + std::to_string(static_cast<int32_t>(item.second.state)) +
            " lastActive=" + std::to_string(item.second.lastActiveTime) + "\n";
    }
    result += "  pending handlers: " + std::to_string(pendingHandlers_.size()) + "\n";
}

} // namespace AppExecFwk
} // namespace OHOS
