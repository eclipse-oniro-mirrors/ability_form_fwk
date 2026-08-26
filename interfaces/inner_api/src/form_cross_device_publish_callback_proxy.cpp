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

#include "form_cross_device_publish_callback_proxy.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "ipc_types.h"
#include "iremote_object.h"
#include <cinttypes>

namespace OHOS {
namespace AppExecFwk {
bool FormCrossDevicePublishCallbackProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(IFormCrossDevicePublishCallback::GetDescriptor())) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    return true;
}

void FormCrossDevicePublishCallbackProxy::OnResult(const PublishFormCrossDeviceResult &result)
{
    HILOG_DEBUG("errCode:%{public}d, formId:%{public}" PRId64, result.errCode, result.formId);
    MessageParcel data;
    if (!WriteInterfaceToken(data) || !data.WriteParcelable(&result)) {
        HILOG_ERROR("write parcelable failed");
        return;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);  // result push, fire-and-forget
    if (!Remote()) {
        HILOG_ERROR("null remoteObj");
        return;
    }
    int32_t error = Remote()->SendRequest(
        static_cast<uint32_t>(IFormCrossDevicePublishCallback::Message::FORM_CD_CALLBACK_ON_RESULT),
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("OnResult SendRequest failed:%{public}d", error);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
