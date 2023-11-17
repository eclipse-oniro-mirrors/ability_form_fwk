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

#include "form_host_delegate_proxy.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "ipc_types.h"

namespace OHOS {
namespace AppExecFwk {
int32_t FormHostDelegateProxy::RouterEvent(const int64_t formId, const Want &want)
{
    MessageParcel data;
    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("Write to interface token error.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt64(formId)) {
        HILOG_ERROR("Write to formId error.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        HILOG_ERROR("Write to want error.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption option;
    int error = Remote()->SendRequest(static_cast<uint32_t>(IFormHostDelegate::Message::FORM_ROUTER_PROXY_MGR),
        data, reply, option);
    if (error != ERR_OK) {
        HILOG_ERROR("Failed to SendRequest: %{public}d", error);
        return ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    }
    return reply.ReadInt32();
}

bool FormHostDelegateProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(FormHostDelegateProxy::GetDescriptor())) {
        HILOG_ERROR("Failed to write interface token.");
        return false;
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
