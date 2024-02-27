/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "form_instance.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormInstance::ReadFromParcel(Parcel &parcel)
{
    formId = parcel.ReadInt64();
    formHostName = Str16ToStr8(parcel.ReadString16());
    formVisiblity = static_cast<FormVisibilityType>(parcel.ReadInt32());
    specification = parcel.ReadInt32();
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    formName = Str16ToStr8(parcel.ReadString16());
    formUsageState = static_cast<FormUsageState>(parcel.ReadInt32());
    description = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool FormInstance::Marshalling(Parcel &parcel) const
{
    // write formId
    if (!parcel.WriteInt64(formId)) {
        return false;
    }

    // write formHostName
    if (!parcel.WriteString16(Str8ToStr16(formHostName))) {
        return false;
    }

    // write formVisiblity
    if (!parcel.WriteInt32(static_cast<int32_t>(formVisiblity))) {
        return false;
    }

    // write specification
    if (!parcel.WriteInt32(specification)) {
        return false;
    }

    // write bundleName
    if (!parcel.WriteString16(Str8ToStr16(bundleName))) {
        return false;
    }

    // write moduleName
    if (!parcel.WriteString16(Str8ToStr16(moduleName))) {
        return false;
    }

    // write abilityName
    if (!parcel.WriteString16(Str8ToStr16(abilityName))) {
        return false;
    }

    // write formName
    if (!parcel.WriteString16(Str8ToStr16(formName))) {
        return false;
    }

    // write formUsageState
    if (!parcel.WriteInt32(static_cast<int32_t>(formUsageState))) {
        return false;
    }

    // write description
    if (!parcel.WriteString16(Str8ToStr16(description))) {
        return false;
    }
    return true;
}

FormInstance* FormInstance::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormInstance> object = std::make_unique<FormInstance>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
