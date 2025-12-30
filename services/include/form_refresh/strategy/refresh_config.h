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

#ifndef OHOS_FORM_FWK_REFRESH_CONFIG_H
#define OHOS_FORM_FWK_REFRESH_CONFIG_H

#include <vector>

namespace OHOS {
namespace AppExecFwk {

/**
 * @enum ControlCheckType
 * Types of control checks
 */
enum ControlCheckType {
    CONTROL_CHECK_NONE = 0,
    CONTROL_CHECK_SYSTEM_OVERLOAD = 1 << 0,
    CONTROL_CHECK_HEALTHY_CONTROL = 1 << 1,
    CONTROL_CHECK_INVISIBLE = 1 << 2,
    CONTROL_CHECK_SCREEN_OFF = 1 << 3,
    CONTROL_CHECK_NEED_TO_FRESH = 1 << 4,
    CONTROL_CHECK_ADD_FINISH = 1 << 5,
};

/**
 * @struct RefreshConfig
 * Configuration for form refresh behavior
 */
struct RefreshConfig {
    // Validation check types
    std::vector<int32_t> checkTypes;

    // Control check flags
    uint32_t controlCheckFlags = 0;
    
    // Control check visibility parameter for IsNeedToFresh
    bool isVisibleToFresh = true;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_REFRESH_CONFIG_H