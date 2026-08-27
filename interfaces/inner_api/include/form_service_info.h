/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_SERVICE_INFO_H
#define OHOS_FORM_FWK_FORM_HOST_SERVICE_INFO_H

#include <cstdint>
#include <string>

#include "errors.h"
#include "form_service_constants.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {

struct FormHostServiceInfo : public Parcelable {
    std::string serviceName;
    std::string serviceDisplayName;
    std::string displayId;
    std::string customData;

    int32_t userId = -1;
    std::string ownerPkgName;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormHostServiceInfo *Unmarshalling(Parcel &parcel);
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HOST_SERVICE_INFO_H
