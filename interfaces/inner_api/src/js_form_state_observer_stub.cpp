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

#include "js_form_state_observer_stub.h"

#include "appexecfwk_errors.h"
#include "hilog_wrapper.h"
#include "form_mgr_errors.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AbilityRuntime {
JsFormStateObserverStub::JsFormStateObserverStub()
{
    memberFuncMap_[static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM)] =
        &JsFormStateObserverStub::HandleOnAddForm;
    memberFuncMap_[static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_REMOVE_FORM)] =
        &JsFormStateObserverStub::HandleOnRemoveForm;
}

JsFormStateObserverStub::~JsFormStateObserverStub()
{
    memberFuncMap_.clear();
}

int32_t JsFormStateObserverStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("JsFormStateObserverStub::OnReceived, code = %{public}u, flags= %{public}d.", code, option.GetFlags());
    std::u16string descriptor = JsFormStateObserverStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("failed, local descriptor is not equal to remote");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    auto itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t JsFormStateObserverStub::HandleOnAddForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::string bundleName = data.ReadString();
    std::unique_ptr<AppExecFwk::RunningFormInfo> runningFormInfo(data.ReadParcelable<AppExecFwk::RunningFormInfo>());
    if (!runningFormInfo) {
        HILOG_ERROR("failed to ReadParcelable<RunningFormInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = OnAddForm(bundleName, *runningFormInfo);
    reply.WriteInt32(result);
    return result;
}

int32_t JsFormStateObserverStub::HandleOnRemoveForm(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("called.");
    std::string bundleName = data.ReadString();
    std::unique_ptr<AppExecFwk::RunningFormInfo> runningFormInfo(data.ReadParcelable<AppExecFwk::RunningFormInfo>());
    if (!runningFormInfo) {
        HILOG_ERROR("failed to ReadParcelable<RunningFormInfo>");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = OnRemoveForm(bundleName, *runningFormInfo);
    reply.WriteInt32(result);
    return result;
}
} // namespace AbilityRuntime
} // namespace OHOS