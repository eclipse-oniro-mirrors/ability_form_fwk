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
    appIndex = parcel.ReadInt32();
    userId = parcel.ReadInt32();
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

    // write appIndex
    if (!parcel.WriteInt32(appIndex)) {
        return false;
    }

    // write userId
    if (!parcel.WriteInt32(userId)) {
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

bool Rect::ReadFromParcel(Parcel &parcel)
{
    left = parcel.ReadDouble();
    top = parcel.ReadDouble();
    width = parcel.ReadDouble();
    height = parcel.ReadDouble();
    HILOG_INFO("call rect: %{public}f, %{public}f, %{public}f, %{public}f", left, top, width, height);
    return true;
}

bool Rect::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteDouble(left)) {
        return false;
    }
    if (!parcel.WriteDouble(top)) {
        return false;
    }
    if (!parcel.WriteDouble(width)) {
        return false;
    }
    if (!parcel.WriteDouble(height)) {
        return false;
    }
    return true;
}

Rect* Rect::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<Rect> object = std::make_unique<Rect>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}

bool OverflowInfo::ReadFromParcel(Parcel &parcel)
{
    if (!area.ReadFromParcel(parcel)) {
        return false;
    }
    duration = parcel.ReadInt32();
    useDefaultAnimation = parcel.ReadBool();
    HILOG_INFO("OverflowInfo, rect: %{public}f, %{public}f, %{public}f, %{public}f, duration: %{public}d,"
        " useDefaultAnimate: %{public}d", area.left, area.top, area.width, area.height, duration, useDefaultAnimation);
    return true;
}

bool OverflowInfo::Marshalling(Parcel &parcel) const
{
    if (!area.Marshalling(parcel)) {
        HILOG_ERROR("Write area failed");
        return false;
    }
    if (!parcel.WriteInt32(duration)) {
        HILOG_ERROR("Write duraion failed");
        return false;
    }
    if (!parcel.WriteBool(useDefaultAnimation)) {
        HILOG_ERROR("Write useDefaultAnimate failed");
        return false;
    }
    return true;
}

OverflowInfo* OverflowInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<OverflowInfo> object = std::make_unique<OverflowInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}

bool PublishFormCrossBundleInfo::ReadFromParcel(Parcel &parcel)
{
    callerBundleName = Str16ToStr8(parcel.ReadString16());
    targetBundleName = Str16ToStr8(parcel.ReadString16());
    targetTemplateFormDetailId = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool PublishFormCrossBundleInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(callerBundleName))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(targetBundleName))) {
        return false;
    }
    if (!parcel.WriteString16(Str8ToStr16(targetTemplateFormDetailId))) {
        return false;
    }
    return true;
}

PublishFormCrossBundleInfo* PublishFormCrossBundleInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<PublishFormCrossBundleInfo> object = std::make_unique<PublishFormCrossBundleInfo>();
    if (object && !object->ReadFromParcel(parcel)) {
        object = nullptr;
        return nullptr;
    }
    return object.release();
}
} // namespace AppExecFwk
} // namespace OHOS
