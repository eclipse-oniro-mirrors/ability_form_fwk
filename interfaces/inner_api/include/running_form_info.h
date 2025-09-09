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

#ifndef OHOS_FORM_FWK_RUNNING_FORM_INFO_H
#define OHOS_FORM_FWK_RUNNING_FORM_INFO_H

#include <singleton.h>
#include <string>

#include "form_instance.h"
#include "parcel.h"
#include "form_constants.h"
#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @struct RunningFormInfo
 * Defines running form info.
 */
struct RunningFormInfo : public Parcelable {
    int64_t formId;
    std::string formName;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string description;
    int32_t dimension;
    std::string hostBundleName;
    Constants::FormLocation formLocation;
    FormVisibilityType formVisiblity = FormVisibilityType::UNKNOWN;
    FormUsageState formUsageState = FormUsageState::USED;
    LowMemoryRecycleStatus lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
    BundleType formBundleType = BundleType::APP;
    int32_t appIndex = 0;
    int32_t userId = -1;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static RunningFormInfo *Unmarshalling(Parcel &parcel);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_RUNNING_FORM_INFO_H
