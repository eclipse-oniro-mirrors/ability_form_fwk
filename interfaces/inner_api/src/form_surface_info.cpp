/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "form_surface_info.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormSurfaceInfo::ReadFromParcel(Parcel &parcel)
{
    width = parcel.ReadFloat();
    height = parcel.ReadFloat();
    borderWidth = parcel.ReadFloat();
    formViewScale = parcel.ReadFloat();
    return true;
}

bool FormSurfaceInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteFloat(width)) {
        HILOG_ERROR("Write width failed");
        return false;
    }
    if (!parcel.WriteFloat(height)) {
        HILOG_ERROR("Write height failed");
        return false;
    }
    if (!parcel.WriteFloat(borderWidth)) {
        HILOG_ERROR("Write borderWidth failed");
        return false;
    }
    if (!parcel.WriteFloat(formViewScale)) {
        HILOG_ERROR("Write formViewScale failed");
        return false;
    }
    return true;
}

FormSurfaceInfo* FormSurfaceInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormSurfaceInfo> object = std::make_unique<FormSurfaceInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
 