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

#ifndef FOUNDATION_APPEXECFWK_OHOS_FORM_SURFACE_INFO_H
#define FOUNDATION_APPEXECFWK_OHOS_FORM_SURFACE_INFO_H

#include <string>
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct FormSurfaceInfo : public Parcelable {
    float width = 0.0f;
    float height = 0.0f;
    float borderWidth = 0.0f;
    float formViewScale = 1.0f;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormSurfaceInfo *Unmarshalling(Parcel &parcel);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_OHOS_FORM_SURFACE_INFO_H
