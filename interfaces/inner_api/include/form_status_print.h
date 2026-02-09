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

#ifndef OHOS_FORM_FWK_FORM_STATUS_PRINT_H
#define OHOS_FORM_FWK_FORM_STATUS_PRINT_H

#include <string>
#include "status_mgr_center/form_status_common.h"

namespace OHOS {
namespace AppExecFwk {
class FormStatusPrint {
public:
    /**
     * @brief Converts a FormFsmStatus enum value to its corresponding string representation.
     * @param status The FormFsmStatus enum value to be converted to a string.
     * @return std::string A string representing the given FormFsmStatus value.
     */
    static std::string FormStatusToString(const FormFsmStatus status);

    /**
     * @brief Converts a FormFsmEvent enum value to its corresponding string representation.
     * @param status The FormFsmEvent enum value to be converted to a string.
     * @return std::string A string representing the given FormFsmEvent value.
     */
    static std::string FormEventToString(const FormFsmEvent event);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_PRINT_H