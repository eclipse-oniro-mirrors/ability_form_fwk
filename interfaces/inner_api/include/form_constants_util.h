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

#ifndef OHOS_FORM_FWK_FORM_CONSTANTS_UTIL_H
#define OHOS_FORM_FWK_FORM_CONSTANTS_UTIL_H

#include <cstdint>
#include <string>

#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
class FormConstantsUtil {
public:
    static const char* GetDimensionString(Constants::Dimension dimension);
    static const char* GetLiveFormActiveState(const std::string &status);
    static bool IsLiveFormSupportLauncher(const std::string &status);
    static bool IsConditionRefreshType(int32_t refreshType);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_CONSTANTS_UTIL_H
