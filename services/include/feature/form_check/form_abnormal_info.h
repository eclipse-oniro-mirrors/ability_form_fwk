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

#ifndef OHOS_FORM_FWK_FORM_ABNORMAL_INFO_H
#define OHOS_FORM_FWK_FORM_ABNORMAL_INFO_H

#include <string>

#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * Form abnormal info.
 */
class FormAbnormalInfo {
public:
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string formName;
    int32_t formDimension;
    int32_t formLocation;
    std::string appVersion;
    // Percentage value of non-transparent areas on the form
    int32_t nonTransparentRatio;

    static FormAbnormalInfo Create(const FormRecord &formRecord)
    {
        FormAbnormalInfo info;
        info.bundleName = formRecord.bundleName;
        info.moduleName = formRecord.moduleName;
        info.abilityName = formRecord.abilityName;
        info.formName = formRecord.formName;
        info.formDimension = formRecord.specification;
        info.formLocation = static_cast<int32_t>(formRecord.formLocation);
        info.appVersion = formRecord.versionName;
        return info;
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_ABNORMAL_INFO_H