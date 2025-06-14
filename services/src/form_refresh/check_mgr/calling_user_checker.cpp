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

#include "form_refresh/check_mgr/calling_user_checker.h"

namespace OHOS {
namespace AppExecFwk {

CallingUserChecker::CallingUserChecker() {}
CallingUserChecker::~CallingUserChecker() {}

int CallingUserChecker::CheckValid(const CheckValidFactor &factor)
{
    if (factor.record.uid != factor.callingUid) {
        HILOG_ERROR("form uid:%{public}d does not match callingUid:%{public}d, formId:%{public}" PRId64,
            factor.record.uid, factor.callingUid, factor.formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS