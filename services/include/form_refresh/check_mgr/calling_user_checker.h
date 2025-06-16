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

#ifndef OHOS_FORM_FWK_CALLING_USER_CHECKER_H
#define OHOS_FORM_FWK_CALLING_USER_CHECKER_H

#include <singleton.h>

#include "form_refresh/check_mgr/base_checker_interface.h"

namespace OHOS {
namespace AppExecFwk {
/**
* @class CallingUserChecker
* CallingUserChecker is used to check form belong to the calling user.
*/
class CallingUserChecker : public IBaseChecker, public DelayedRefSingleton<CallingUserChecker> {
    DECLARE_DELAYED_REF_SINGLETON(CallingUserChecker);
public:
    DISALLOW_COPY_AND_MOVE(CallingUserChecker);

    int CheckValid(const CheckValidFactor &factor) override;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_CALLING_USER_CHECKER_H