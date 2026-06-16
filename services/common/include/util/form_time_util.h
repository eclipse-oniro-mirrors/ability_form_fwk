/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_TIME_UTIL_H
#define OHOS_FORM_FWK_TIME_UTIL_H

#include <cstdint>

namespace OHOS {
namespace AppExecFwk {
namespace Common {

/**
 * @brief Form time utility class
 *
 * Provides common time-related utilities that can be shared between
 * FMS (Form Manager Service) and FRS (Form Render Service).
 *
 * This class consolidates time utilities from both FormTimerUtil and
 * other time-related helper functions.
 */
class FormTimeUtil {
public:
    /**
     * @brief Get system boot time in milliseconds
     * @return Boot time in milliseconds since system boot
     */
    static int64_t GetBootTimeMs();

    /**
     * @brief Get current time in milliseconds
     * @return Current time in milliseconds since epoch
     */
    static int64_t GetNowMillisecond();
};

} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_TIME_UTIL_H