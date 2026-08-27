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

#ifndef OHOS_FORM_FWK_FORM_SOFTBUS_SESSION_REGISTRY_H
#define OHOS_FORM_FWK_FORM_SOFTBUS_SESSION_REGISTRY_H

#include <map>
#include <memory>
#include <mutex>
#include <singleton.h>

#include "socket.h"
#include "trans_type.h"

namespace OHOS {
namespace AppExecFwk {
// SoftBus ISocketListener is C function-pointer table; events are routed through
// FormSoftbusSessionRegistry trampolines that map fd back to this C++ interface.
class ISocketSession {
public:
    virtual ~ISocketSession() = default;
    virtual void OnServiceBind(int32_t fd, ServiceSocketInfo info) = 0;
    virtual bool OnServiceNegotiate(int32_t fd, ServiceSocketInfo info) = 0;
    virtual void OnBytes(int32_t fd, const void *data, uint32_t len) = 0;
    virtual void OnShutdown(int32_t fd, ShutdownReason reason) = 0;
    virtual void OnError(int32_t fd, int32_t errCode) = 0;
};

// SoftBus OnServiceBind/OnBytes may fire on Listen fd or accepted connection fd; single Server handles both.
class FormSoftbusSessionRegistry {
public:
    static FormSoftbusSessionRegistry &Instance();
    void RegisterServer(const std::shared_ptr<ISocketSession> &server);
    void UnregisterServer();
    void RegisterClient(int32_t fd, const std::shared_ptr<ISocketSession> &session);
    void UnregisterClient(int32_t fd);
    std::shared_ptr<ISocketSession> Find(int32_t fd);
    static const ISocketListener &Listener();

private:
    FormSoftbusSessionRegistry() = default;
    ~FormSoftbusSessionRegistry() = default;
    DISALLOW_COPY_AND_MOVE(FormSoftbusSessionRegistry);
    friend class DelayedRefSingleton<FormSoftbusSessionRegistry>;

    std::mutex mutex_;
    std::weak_ptr<ISocketSession> serverSession_;
    std::map<int32_t, std::weak_ptr<ISocketSession>> clientMap_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_SOFTBUS_SESSION_REGISTRY_H
