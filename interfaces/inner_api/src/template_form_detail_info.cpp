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
#include "template_form_detail_info.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
bool ReadStringField(Parcel &parcel, const char *fieldName, std::string &out, size_t maxLength = 0)
{
    std::u16string u16;
    if (!parcel.ReadString16(u16)) {
        HILOG_ERROR("read %{public}s failed", fieldName);
        return false;
    }
    out = Str16ToStr8(u16);
    if (maxLength > 0 && (out.empty() || out.size() > maxLength)) {
        HILOG_ERROR("invalid %{public}s, length:%{public}zu", fieldName, out.size());
        return false;
    }
    return true;
}
} // namespace

bool TemplateFormDetailInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(bundleName))) {
        HILOG_ERROR("marshal bundleName failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(moduleName))) {
        HILOG_ERROR("marshal moduleName failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(abilityName))) {
        HILOG_ERROR("marshal abilityName failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(formName))) {
        HILOG_ERROR("marshal formName failed");
        return false;
    }

    if (!parcel.WriteInt32(dimension)) {
        HILOG_ERROR("marshal dimension failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(detailId))) {
        HILOG_ERROR("marshal detailId failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(displayName))) {
        HILOG_ERROR("marshal displayName failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(description))) {
        HILOG_ERROR("marshal description failed");
        return false;
    }

    return true;
}

bool TemplateFormDetailInfo::ReadFromParcel(Parcel &parcel)
{
    if (!ReadStringField(parcel, "bundleName", bundleName, Constants::MAX_BUNDLE_NAME_LENGTH) ||
        !ReadStringField(parcel, "moduleName", moduleName, Constants::MAX_MODULE_NAME_LENGTH) ||
        !ReadStringField(parcel, "abilityName", abilityName, Constants::MAX_ABILITY_NAME_LENGTH) ||
        !ReadStringField(parcel, "formName", formName, Constants::MAX_FORM_NAME_LENGTH)) {
        return false;
    }
    if (!parcel.ReadInt32(dimension)) {
        HILOG_ERROR("read dimension failed");
        return false;
    }
    if (!ReadStringField(parcel, "detailId", detailId) ||
        !ReadStringField(parcel, "displayName", displayName) ||
        !ReadStringField(parcel, "description", description)) {
        return false;
    }
    return true;
}

TemplateFormDetailInfo *TemplateFormDetailInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<TemplateFormDetailInfo> templateFormDetailInfo = std::make_unique<TemplateFormDetailInfo>();
    if (!templateFormDetailInfo->ReadFromParcel(parcel)) {
        templateFormDetailInfo = nullptr;
        return nullptr;
    }
    return templateFormDetailInfo.release();
}
} // OHOS
} // AppExecFwk
