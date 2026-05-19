/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_record_filter.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

bool FormRecordFilter::Marshalling(Parcel &parcel) const
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
    return true;
}

bool FormRecordFilter::ReadFromParcel(Parcel &parcel)
{
    std::u16string str;
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read bundleName failed");
        return false;
    }
    bundleName = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read moduleName failed");
        return false;
    }
    moduleName = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read abilityName failed");
        return false;
    }
    abilityName = Str16ToStr8(str);
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read formName failed");
        return false;
    }
    formName = Str16ToStr8(str);
    return true;
}

FormRecordFilter *FormRecordFilter::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormRecordFilter> filter = std::make_unique<FormRecordFilter>();
    if (!filter->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return filter.release();
}

} // namespace AppExecFwk
} // namespace OHOS
