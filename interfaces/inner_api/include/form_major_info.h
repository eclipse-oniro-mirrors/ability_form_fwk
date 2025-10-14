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
#ifndef OHOS_FORM_FWK_FORM_MAJOR_INFO_H
#define OHOS_FORM_FWK_FORM_MAJOR_INFO_H

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

struct FormMajorInfo final : public Parcelable {
    std::string bundleName = "";
    std::string moduleName = "";
    std::string abilityName = "";
    std::string formName = "";
    int32_t dimension = 0;

    bool Marshalling(Parcel &parcel) const override;
    static FormMajorInfo *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif