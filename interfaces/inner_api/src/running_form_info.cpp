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

#include "running_form_info.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool RunningFormInfo::ReadFromParcel(Parcel &parcel)
{
    formId = parcel.ReadInt64();
    formName = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    description = parcel.ReadString();
    dimension = parcel.ReadInt32();
    hostBundleName = Str16ToStr8(parcel.ReadString16());
    int32_t formVisiblityInt = parcel.ReadInt32();
    formVisiblity = (FormVisibilityType)formVisiblityInt;
    formUsageState = static_cast<FormUsageState>(parcel.ReadInt32());
    formLocation = static_cast<Constants::FormLocation>(parcel.ReadInt32());
    return true;
}

bool RunningFormInfo::Marshalling(Parcel &parcel) const
{
    // write formId
    if (!parcel.WriteInt64(formId)) {
        return false;
    }

    // write formName
    if (!parcel.WriteString16(Str8ToStr16(formName))) {
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

    // write description
    if (!parcel.WriteString(description)) {
        return false;
    }

    // write dimension
    if (!parcel.WriteInt32(dimension)) {
        return false;
    }

    // write hostBundleName
    if (!parcel.WriteString16(Str8ToStr16(hostBundleName))) {
        return false;
    }

    // write formVisiblity
    if (!parcel.WriteInt32((int32_t)formVisiblity)) {
        return false;
    }

    // write formUsageState
    if (!parcel.WriteInt32(static_cast<int32_t>(formUsageState))) {
        return false;
    }

    // write formLocation
    if (!parcel.WriteInt32(static_cast<int32_t>(formLocation))) {
        return false;
    }
    return true;
}

RunningFormInfo* RunningFormInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<RunningFormInfo> object = std::make_unique<RunningFormInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
