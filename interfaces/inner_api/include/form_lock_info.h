/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_LOCK_INFO_H
#define OHOS_FORM_FWK_FORM_LOCK_INFO_H

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @enum LockChangeType
 * Defines form lock change type.
 * The difference is that the application lock switch status and protection status change.
 * When the application lock switch of the application changes, SWITCH_CHANGE is used.
 * When the protection status changes, it is used. When the switch status changes, the protection status also changes.
 */
enum class LockChangeType : int32_t {
    INVALID_PARAMETER = -1,
    SWITCH_CHANGE = 0,
    PROTECT_CHANGE
};

struct FormLockInfo final : public Parcelable {
    std::string bundleName = "";
    int32_t userId = 0;
    bool lock = false;

    bool Marshalling(Parcel &parcel) const override;

    static FormLockInfo *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif