/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_DELEGATE_PROXY_H
#define OHOS_FORM_FWK_FORM_HOST_DELEGATE_PROXY_H

#include "form_host_delegate_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class FormHostDelegateProxy : public IRemoteProxy<IFormHostDelegate> {
public:
    explicit FormHostDelegateProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IFormHostDelegate>(impl)
    {}
    virtual ~FormHostDelegateProxy() = default;

    /**
     * @brief The form router event.
     * @param want The want to start ability.
     */
    int32_t RouterEvent(const int64_t formId, const Want &want) override;
private:
    bool WriteInterfaceToken(MessageParcel &data);
    static inline BrokerDelegator<FormHostDelegateProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_HOST_DELEGATE_PROXY_H