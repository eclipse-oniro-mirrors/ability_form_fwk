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

#ifndef FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCES_FILTER_H
#define FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCES_FILTER_H

#include <string>
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct FormInstancesFilter : public Parcelable {
    std::string bundleName;
    std::string formName;
    std::string moduleName;
    std::string abilityName;
    bool isUnusedIncluded = false;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormInstancesFilter *Unmarshalling(Parcel &parcel);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCES_FILTER_H