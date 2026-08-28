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

#include "form_cross_device_publish_callback_stub.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
FormCrossDevicePublishCallbackStub::FormCrossDevicePublishCallbackStub()
{}

FormCrossDevicePublishCallbackStub::~FormCrossDevicePublishCallbackStub()
{}

int FormCrossDevicePublishCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("code=%{public}u, flags=%{public}d", code, option.GetFlags());
    std::u16string descriptor = FormCrossDevicePublishCallbackStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("localDescriptor not equal to remote");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t callerUid = IPCSkeleton::GetCallingUid();
    if (callerUid != FormConstants::FOUNDATION_UID) {
        HILOG_ERROR("caller uid %{public}d is not foundation, rejected", callerUid);
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }

    switch (code) {
        case static_cast<uint32_t>(IFormCrossDevicePublishCallback::Message::FORM_CD_CALLBACK_ON_RESULT):
            return HandleOnResult(data, reply);
        default:
            HILOG_ERROR("unsupported code:%{public}u", code);
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
}

int32_t FormCrossDevicePublishCallbackStub::HandleOnResult(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<PublishFormCrossDeviceResult> result(data.ReadParcelable<PublishFormCrossDeviceResult>());
    if (result == nullptr) {
        HILOG_ERROR("read PublishFormCrossDeviceResult failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    OnResult(*result);
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
