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

#include "form_publish_interceptor_stub.h"

#include "appexecfwk_errors.h"
#include "errors.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
FormPublishInterceptorStub::FormPublishInterceptorStub()
{
    memberFuncMap_[static_cast<uint32_t>(IFormPublishInterceptor::Message::FORM_PROCESS_PUBLISH_FORM)] =
        &FormPublishInterceptorStub::HandleProcessPublishForm;
}

FormPublishInterceptorStub::~FormPublishInterceptorStub()
{
    memberFuncMap_.clear();
}

int FormPublishInterceptorStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_INFO("OnReceived, code = %{public}u, flags= %{public}d.",
        code, option.GetFlags());
    std::u16string descriptor = FormPublishInterceptorStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("local descriptor is not equal to remote");
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

int FormPublishInterceptorStub::HandleProcessPublishForm(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        HILOG_ERROR("ReadParcelable<Want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t result = ProcessPublishForm(*want);
    reply.WriteInt32(result);
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS