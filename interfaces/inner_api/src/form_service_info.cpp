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

#include "form_service_info.h"

#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormHostServiceInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string str;
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read serviceName failed");
        return false;
    }
    serviceName = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read serviceDisplayName failed");
        return false;
    }
    serviceDisplayName = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read displayId failed");
        return false;
    }
    displayId = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read customData failed");
        return false;
    }
    customData = Str16ToStr8(str);
    if (!parcel.ReadInt32(userId)) {
        HILOG_ERROR("read userId failed");
        return false;
    }
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read ownerPkgName failed");
        return false;
    }
    ownerPkgName = Str16ToStr8(str);
    return true;
}

bool FormHostServiceInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(serviceName))) {
        HILOG_ERROR("write serviceName failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(serviceDisplayName))) {
        HILOG_ERROR("write serviceDisplayName failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(displayId))) {
        HILOG_ERROR("write displayId failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(customData))) {
        HILOG_ERROR("write customData failed");
        return false;
    }
    if (!parcel.WriteInt32(userId)) {
        HILOG_ERROR("write userId failed");
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(ownerPkgName))) {
        HILOG_ERROR("write ownerPkgName failed");
        return false;
    }
    return true;
}

FormHostServiceInfo *FormHostServiceInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormHostServiceInfo> object = std::make_unique<FormHostServiceInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
