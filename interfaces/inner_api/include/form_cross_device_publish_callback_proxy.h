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

#ifndef OHOS_FORM_FWK_FORM_CROSS_DEVICE_PUBLISH_CALLBACK_PROXY_H
#define OHOS_FORM_FWK_FORM_CROSS_DEVICE_PUBLISH_CALLBACK_PROXY_H

#include "form_cross_device_request.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormCrossDevicePublishCallbackProxy
 * Held by FMS to push cross-device publish results back to the caller via IPC.
 */
class FormCrossDevicePublishCallbackProxy : public IRemoteProxy<IFormCrossDevicePublishCallback> {
public:
    explicit FormCrossDevicePublishCallbackProxy(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<IFormCrossDevicePublishCallback>(impl)
    {}
    virtual ~FormCrossDevicePublishCallbackProxy() = default;

    void OnResult(const PublishFormCrossDeviceResult &result) override;

private:
    bool WriteInterfaceToken(MessageParcel &data);

private:
    static inline BrokerDelegator<FormCrossDevicePublishCallbackProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CROSS_DEVICE_PUBLISH_CALLBACK_PROXY_H
