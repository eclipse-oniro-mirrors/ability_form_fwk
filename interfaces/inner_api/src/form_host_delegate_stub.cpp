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

#include "form_host_delegate_stub.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
FormHostDelegateStub::FormHostDelegateStub()
{
    memberFuncMap_[static_cast<uint32_t>(IFormHostDelegate::Message::FORM_ROUTER_PROXY_MGR)] =
        &FormHostDelegateStub::HandleRouterEvent;
}

FormHostDelegateStub::~FormHostDelegateStub()
{
    memberFuncMap_.clear();
}

int32_t FormHostDelegateStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    HILOG_INFO("FormHostDelegateStub::OnReceived, code = %{public}u, flags= %{public}d.", code, option.GetFlags());
    std::u16string descriptor = FormHostDelegateStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("Failed, local descriptor is not equal to remote");
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

int32_t FormHostDelegateStub::HandleRouterEvent(MessageParcel &data, MessageParcel &reply)
{
    HILOG_DEBUG("Called.");
    int64_t formId = data.ReadInt64();
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        HILOG_ERROR("Failed to ReadParcelable<Want>.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto result = RouterEvent(formId, *want);
    reply.WriteInt32(result);
    return result;
}
} // namespace AppExecFwk
} // namespace OHOS