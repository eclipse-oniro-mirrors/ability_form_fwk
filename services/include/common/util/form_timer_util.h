/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#ifndef OHOS_FORM_FWK_FORM_TIMER_UTIL_H
#define OHOS_FORM_FWK_FORM_TIMER_UTIL_H

#include <cinttypes>

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormTimerUtil
 * form timer utils.
 */
class FormTimerUtil {
public:
    /**
     * @brief Get the number of milliseconds elapsed since the system started.
     * @return the number of milliseconds.
     */
    static int64_t GetBootTimeMs();
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_TIMER_UTIL_H
