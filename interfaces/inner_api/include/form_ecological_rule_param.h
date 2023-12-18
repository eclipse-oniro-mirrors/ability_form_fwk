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

#ifndef FORM_ECOLOGICAL_RULE_PARAM_H
#define FORM_ECOLOGICAL_RULE_PARAM_H

#include <string>
#include <vector>

#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

struct FormErmsCallerInfo : public Parcelable {
    enum {
        TYPE_INVALID = 0,
        TYPE_HARMONY_APP,
        TYPE_ATOM_SERVICE,
        TYPE_QUICK_APP = 4,
        TYPE_BOXED_ATOM_SERVICE
    };

    std::string packageName;
    int32_t uid = 0L;
    int32_t pid = 0L;

    int32_t callerAppType = TYPE_INVALID;
    int32_t targetAppType = TYPE_INVALID;

    bool ReadFromParcel(Parcel &parcel);

    bool Marshalling(Parcel &parcel) const override;

    static FormErmsCallerInfo *Unmarshalling(Parcel &parcel);

    std::string ToString() const;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FORM_ECOLOGICAL_RULE_PARAM_H
