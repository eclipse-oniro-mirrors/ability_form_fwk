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

#include "form_publish_interceptor_proxy.h"

#include "appexecfwk_errors.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
int32_t FormPublishInterceptorProxy::ProcessPublishForm(const AAFwk::Want &want)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!data.WriteInterfaceToken(FormPublishInterceptorProxy::GetDescriptor())) {
        HILOG_ERROR("failed to write interface token");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("failed to write want");
        return ERR_FLATTEN_OBJECT;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("remote object is nullptr.");
        return ERR_NULL_OBJECT;
    }

    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IFormPublishInterceptor::Message::FORM_PROCESS_PUBLISH_FORM),
        data,
        reply,
        option);
    if (error != ERR_OK) {
        HILOG_ERROR("failed to SendRequest: %{public}d", error);
        return error;
    }
    int32_t result = reply.ReadInt32();
    HILOG_DEBUG("get result from server data = %{public}d", result);
    return result;
}
}  // namespace AppExecFwk
}  // namespace OHOS
