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
#include "string_ex.h"
 
namespace OHOS {
namespace AppExecFwk {
bool TemplateFormDetailInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(bundleName))) {
        HILOG_ERROR("marshall bundleName failed");
        return false;
    }

    if (!parcel.WriteString16(Str8ToStr16(moduleName))) {
        HILOG_ERROR("marshall moduleName failed");
        return false;
    }
 
    if (!parcel.WriteString16(Str8ToStr16(abilityName))) {
        HILOG_ERROR("marshall abilityName failed");
        return false;
    }
 
    if (!parcel.WriteString16(Str8ToStr16(formName))) {
        HILOG_ERROR("marshall formName failed");
        return false;
    }

    if (!parcel.WriteInt32(dimension)) {
        HILOG_ERROR("marshall dimension failed");
        return false;
    }
 
    if (!parcel.WriteString16(Str8ToStr16(detailId))) {
        HILOG_ERROR("marshall detailId failed");
        return false;
    }
 
    if (!parcel.WriteString16(Str8ToStr16(displayName))) {
        HILOG_ERROR("marshall displayName failed");
        return false;
    }
 
    if (!parcel.WriteString16(Str8ToStr16(description))) {
        HILOG_ERROR("marshall description failed");
        return false;
    }
 
    return true;
}
 
bool TemplateFormDetailInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    formName = Str16ToStr8(parcel.ReadString16());
    dimension = parcel.ReadInt32();
    detailId = Str16ToStr8(parcel.ReadString16());
    displayName = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    return true;
}
 
TemplateFormDetailInfo *TemplateFormDetailInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<TemplateFormDetailInfo> templateFormDetailInfo = std::make_unique<TemplateFormDetailInfo>();
    if (templateFormDetailInfo && !templateFormDetailInfo->ReadFromParcel(parcel)) {
        templateFormDetailInfo = nullptr;
        return nullptr;
    }
    return templateFormDetailInfo.release();
}
} // OHOS
} // AppExecFwk
