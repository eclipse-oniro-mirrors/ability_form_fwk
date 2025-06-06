/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "form_info_filter.h"
#include "fms_log_wrapper.h"
// for string conversions
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormInfoFilter::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString16(Str8ToStr16(moduleName))) {
        HILOG_ERROR("marshall moduleNamen failed");
        return false;
    }
    return true;
}

FormInfoFilter *FormInfoFilter::Unmarshalling(Parcel &parcel)
{
    FormInfoFilter *filter = new (std::nothrow) FormInfoFilter();

    if (filter != nullptr) {
        // deserializations
        filter->moduleName = Str16ToStr8(parcel.ReadString16());
    }

    return filter;
}
} // OHOS
} // AppExecFwk