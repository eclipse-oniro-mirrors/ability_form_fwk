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

#ifndef OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_PROXY_H
#define OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_PROXY_H

#include "js_form_state_observer_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AbilityRuntime {
class JsFormStateObserverProxy : public IRemoteProxy<IJsFormStateObserver> {
public:
    explicit JsFormStateObserverProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IJsFormStateObserver>(impl)
    {}
    virtual ~JsFormStateObserverProxy() = default;

    /**
     * @brief The form added.
     * @param bundleName The bundle name of the form host.
     */
    virtual int32_t OnAddForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    /**
     * @brief The form removed.
     * @param bundleName The bundle name of the form host.
     */
    virtual int32_t OnRemoveForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    /**
     * @brief The form click event.
     * @param bundleName BundleName of the form host.
     * @param callType The click event type.
     * @param runningFormInfo The running form info.
     */
    virtual int32_t OnFormClickEvent(
        const std::string &bundleName, const std::string &callType, const AppExecFwk::RunningFormInfo &runningFormInfo);

    virtual int32_t NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &runningFormInfos);

private:
    static inline BrokerDelegator<JsFormStateObserverProxy> delegator_;
    int SendTransactCmd(IJsFormStateObserver::Message code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_PROXY_H
