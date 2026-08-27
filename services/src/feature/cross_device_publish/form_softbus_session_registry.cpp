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

#include "feature/cross_device_publish/form_softbus_session_registry.h"

#include "fms_log_wrapper.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
void TrampOnServiceBind(int32_t socket, ServiceSocketInfo info)
{
    HILOG_INFO("TrampOnServiceBind: fd=%{public}d peerSvcId=%{public}" PRId64, socket, info.peerServiceId);
    auto s = FormSoftbusSessionRegistry::Instance().Find(socket);
    if (s) {
        s->OnServiceBind(socket, info);
    } else {
        HILOG_WARN("TrampOnServiceBind: session not found for fd=%{public}d", socket);
    }
}
bool TrampOnServiceNegotiate(int32_t socket, ServiceSocketInfo info)
{
    HILOG_INFO("TrampOnServiceNegotiate: fd=%{public}d peerSvcId=%{public}" PRId64, socket, info.peerServiceId);
    auto s = FormSoftbusSessionRegistry::Instance().Find(socket);
    // Prevent orphan connections.
    if (!s) {
        HILOG_WARN("TrampOnServiceNegotiate: session not found for fd=%{public}d, reject", socket);
        return false;
    }
    return s->OnServiceNegotiate(socket, info);
}
void TrampOnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    auto s = FormSoftbusSessionRegistry::Instance().Find(socket);
    if (s) {
        s->OnBytes(socket, data, dataLen);
    }
}
void TrampOnShutdown(int32_t socket, ShutdownReason reason)
{
    auto s = FormSoftbusSessionRegistry::Instance().Find(socket);
    if (s) {
        s->OnShutdown(socket, reason);
    }
}
void TrampOnError(int32_t socket, int32_t errCode)
{
    auto s = FormSoftbusSessionRegistry::Instance().Find(socket);
    if (s) {
        s->OnError(socket, errCode);
    }
}
// Stub: SoftBus never calls OnBind for ServiceSocket, but IsValidSocketListener requires non-NULL.
void TrampOnBind(int32_t socket, PeerSocketInfo info)
{
    HILOG_WARN("OnBind called on ServiceSocket (unexpected), fd=%{public}d", socket);
}
} // namespace

FormSoftbusSessionRegistry &FormSoftbusSessionRegistry::Instance()
{
    return DelayedRefSingleton<FormSoftbusSessionRegistry>::GetInstance();
}

void FormSoftbusSessionRegistry::RegisterServer(const std::shared_ptr<ISocketSession> &server)
{
    std::lock_guard<std::mutex> lock(mutex_);
    serverSession_ = server;
}

void FormSoftbusSessionRegistry::UnregisterServer()
{
    std::lock_guard<std::mutex> lock(mutex_);
    serverSession_.reset();
}

void FormSoftbusSessionRegistry::RegisterClient(int32_t fd, const std::shared_ptr<ISocketSession> &session)
{
    if (fd < 0 || session == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    clientMap_[fd] = session;
}

void FormSoftbusSessionRegistry::UnregisterClient(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    clientMap_.erase(fd);
}

std::shared_ptr<ISocketSession> FormSoftbusSessionRegistry::Find(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clientMap_.find(fd);
    if (it != clientMap_.end()) {
        auto locked = it->second.lock();
        if (locked) {
            return locked;
        }
        // Expired entry, clean up
        clientMap_.erase(it);
    }
    return serverSession_.lock();
}

const ISocketListener &FormSoftbusSessionRegistry::Listener()
{
    static ISocketListener listener;
    static std::once_flag once;
    std::call_once(once, []() {
        listener = ISocketListener{};
        listener.OnBind = TrampOnBind;
        listener.OnServiceBind = TrampOnServiceBind;
        listener.OnServiceNegotiate = TrampOnServiceNegotiate;
        listener.OnBytes = TrampOnBytes;
        listener.OnShutdown = TrampOnShutdown;
        listener.OnError = TrampOnError;
    });
    return listener;
}
} // namespace AppExecFwk
} // namespace OHOS
