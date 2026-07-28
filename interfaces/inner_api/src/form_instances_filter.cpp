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

#include "form_instances_filter.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormInstancesFilter::ReadFromParcel(Parcel &parcel)
{
    std::u16string bundleNameStr;
    if (!parcel.ReadString16(bundleNameStr)) {
        return false;
    }
    bundleName = Str16ToStr8(bundleNameStr);
    std::u16string formNameStr;
    if (!parcel.ReadString16(formNameStr)) {
        return false;
    }
    formName = Str16ToStr8(formNameStr);
    std::u16string moduleNameStr;
    if (!parcel.ReadString16(moduleNameStr)) {
        return false;
    }
    moduleName = Str16ToStr8(moduleNameStr);
    std::u16string abilityNameStr;
    if (!parcel.ReadString16(abilityNameStr)) {
        return false;
    }
    abilityName = Str16ToStr8(abilityNameStr);
    if (!parcel.ReadBool(isUnusedIncluded)) {
        return false;
    }
    return true;
}

bool FormInstancesFilter::Marshalling(Parcel &parcel) const
{
    // write bundleName
    if (!parcel.WriteString16(Str8ToStr16(bundleName))) {
        return false;
    }

    // write formName
    if (!parcel.WriteString16(Str8ToStr16(formName))) {
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

    // write isUnusedIncluded
    if (!parcel.WriteBool(isUnusedIncluded)) {
        return false;
    }

    return true;
}

FormInstancesFilter* FormInstancesFilter::Unmarshalling(Parcel &parcel)
{
    FormInstancesFilter* object = new (std::nothrow) FormInstancesFilter();
    if (object && !object->ReadFromParcel(parcel)) {
        delete object;
        object = nullptr;
    }
    return object;
}
} // namespace AppExecFwk
} // namespace OHOS
