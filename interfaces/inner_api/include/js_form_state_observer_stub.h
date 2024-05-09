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

#ifndef OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_STUB_H
#define OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_STUB_H

#include <map>
#include <mutex>
#include <vector>
#include "js_form_state_observer_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AbilityRuntime {
class JsFormStateObserverStub : public IRemoteStub<IJsFormStateObserver> {
public:
    JsFormStateObserverStub();
    virtual ~JsFormStateObserverStub();

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int32_t HandleOnAddForm(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnRemoveForm(MessageParcel &data, MessageParcel &reply);

    int32_t HandleNotifyWhetherFormsVisible(MessageParcel &data, MessageParcel &reply);

    int32_t HandleOnFormClick(MessageParcel &data, MessageParcel &reply);
private:
    using FormStateObserverFunc = int32_t (JsFormStateObserverStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, FormStateObserverFunc> memberFuncMap_;

    DISALLOW_COPY_AND_MOVE(JsFormStateObserverStub);
template<typename T>
    int32_t GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_STUB_H
