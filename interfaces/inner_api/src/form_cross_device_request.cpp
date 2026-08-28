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

#include "form_cross_device_request.h"

#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormCrossDeviceRequest::ReadFromParcel(Parcel &parcel)
{
    std::u16string str;
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read peerNetworkId failed");
        return false;
    }
    peerNetworkId = Str16ToStr8(str);
    if (!parcel.ReadInt64(peerServiceId)) {
        HILOG_ERROR("read peerServiceId failed");
        return false;
    }
    std::unique_ptr<OHOS::AAFwk::Want> wantPtr(parcel.ReadParcelable<OHOS::AAFwk::Want>());
    if (wantPtr == nullptr) {
        HILOG_ERROR("read Want failed");
        return false;
    }
    want = std::move(*wantPtr);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read formProviderData failed");
        return false;
    }
    formProviderData = Str16ToStr8(str);
    return true;
}

bool FormCrossDeviceRequest::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(peerNetworkId))) {
        HILOG_ERROR("write peerNetworkId failed");
        return false;
    }
    if (!parcel.WriteInt64(peerServiceId)) {
        HILOG_ERROR("write peerServiceId failed");
        return false;
    }
    if (!parcel.WriteParcelable(&want)) {
        HILOG_ERROR("write Want failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(formProviderData))) {
        HILOG_ERROR("write formProviderData failed");
        return false;
    }
    return true;
}

FormCrossDeviceRequest *FormCrossDeviceRequest::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormCrossDeviceRequest> object = std::make_unique<FormCrossDeviceRequest>();
    if (object && !object->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return object.release();
}

bool PublishFormCrossDeviceResult::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadInt32(errCode)) {
        HILOG_ERROR("read errCode failed");
        return false;
    }
    if (!parcel.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return false;
    }
    return true;
}

bool PublishFormCrossDeviceResult::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(errCode)) {
        return false;
    }
    if (!parcel.WriteInt64(formId)) {
        return false;
    }
    return true;
}

PublishFormCrossDeviceResult *PublishFormCrossDeviceResult::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<PublishFormCrossDeviceResult> object = std::make_unique<PublishFormCrossDeviceResult>();
    if (object && !object->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
