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
#include "form_custom_config.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {

bool FormCustomConfig::Marshalling(Parcel &parcel) const
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

    if (!parcel.WriteString16(Str8ToStr16(relatedBundleName))) {
        HILOG_ERROR("marshal relatedBundleName failed");
        return false;
    }

    if (!parcel.WriteBool(isShowInFormCenter)) {
        HILOG_ERROR("marshal isShowInFormCenter failed");
        return false;
    }

    if (!parcel.WriteBool(isRepeatAdditionSupported)) {
        HILOG_ERROR("marshal isRepeatAdditionSupported failed");
        return false;
    }

    return true;
}

bool FormCustomConfig::ReadFromParcel(Parcel &parcel)
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
    if (!parcel.ReadString16(str)) {
        HILOG_ERROR("read relatedBundleName failed");
        return false;
    }
    relatedBundleName = Str16ToStr8(str);
    if (!parcel.ReadBool(isShowInFormCenter)) {
        HILOG_ERROR("read isShowInFormCenter failed");
        return false;
    }
    if (!parcel.ReadBool(isRepeatAdditionSupported)) {
        HILOG_ERROR("read isRepeatAdditionSupported failed");
        return false;
    }
    return true;
}

FormCustomConfig *FormCustomConfig::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormCustomConfig> config = std::make_unique<FormCustomConfig>();
    if (!config->ReadFromParcel(parcel)) {
        return nullptr;
    }
    return config.release();
}

} // namespace AppExecFwk
} // namespace OHOS
