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
#include "form_major_info.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormMajorInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName)) {
        HILOG_ERROR("marshall bundleName failed");
        return false;
    }

    if (!parcel.WriteString(moduleName)) {
        HILOG_ERROR("marshall moduleName failed");
        return false;
    }

    if (!parcel.WriteString(abilityName)) {
        HILOG_ERROR("marshall abilityName failed");
        return false;
    }

    if (!parcel.WriteString(formName)) {
        HILOG_ERROR("marshall formName failed");
        return false;
    }

    if (!parcel.WriteInt32(dimension)) {
        HILOG_ERROR("marshall dimension failed");
        return false;
    }

    return true;
}

FormMajorInfo *FormMajorInfo::Unmarshalling(Parcel &parcel)
{
    FormMajorInfo *majorInfo = new (std::nothrow) FormMajorInfo();

    if (majorInfo == nullptr) {
        HILOG_ERROR("new FormMajorInfo failed.");
        return nullptr;
    }

    bool readFlag = false;
    do {
        if (!parcel.ReadString(majorInfo->bundleName)) {
            HILOG_ERROR("marshall bundleName failed.");
            break;
        }

        if (!parcel.ReadString(majorInfo->moduleName)) {
            HILOG_ERROR("marshall moduleName failed.");
            break;
        }

        if (!parcel.ReadString(majorInfo->abilityName)) {
            HILOG_ERROR("marshall abilityName failed.");
            break;
        }

        if (!parcel.ReadString(majorInfo->formName)) {
            HILOG_ERROR("marshall formName failed.");
            break;
        }

        if (!parcel.ReadInt32(majorInfo->dimension)) {
            HILOG_ERROR("marshall dimension failed.");
            break;
        }

        readFlag = true;
    } while (0);

    if (!readFlag) {
        delete majorInfo;
        majorInfo = nullptr;
        return majorInfo;
    }
    return majorInfo;
}
} // OHOS
} // AppExecFwk