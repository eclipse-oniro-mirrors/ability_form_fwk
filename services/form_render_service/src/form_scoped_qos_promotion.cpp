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

#include "form_scoped_qos_promotion.h"

#include "qos.h"
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
FormScopedQosPromotion::FormScopedQosPromotion(int32_t formLocation)
{
    promotePriority_ = formLocation == static_cast<int32_t>(Constants::FormLocation::FORM_CENTER) ||
                       formLocation == static_cast<int32_t>(Constants::FormLocation::FORM_MANAGER);
    if (promotePriority_) {
        OHOS::QOS::SetThreadQos(QOS::QosLevel::QOS_USER_INTERACTIVE);
    }
}

FormScopedQosPromotion::~FormScopedQosPromotion()
{
    if (promotePriority_) {
        OHOS::QOS::SetThreadQos(QOS::QosLevel::QOS_DEADLINE_REQUEST);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
