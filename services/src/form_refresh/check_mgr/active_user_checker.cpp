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

#include "form_refresh/check_mgr/active_user_checker.h"

#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {

ActiveUserChecker::ActiveUserChecker() {}
ActiveUserChecker::~ActiveUserChecker() {}

int ActiveUserChecker::CheckValid(const CheckValidFactor &factor)
{
    int32_t currentActiveUserId = Constants::DEFAULT_PROVIDER_USER_ID;
    if (factor.want.HasParameter(Constants::PARAM_FORM_USER_ID)) {
        currentActiveUserId = factor.want.GetIntParam(Constants::PARAM_FORM_USER_ID,
            Constants::DEFAULT_PROVIDER_USER_ID);
    } else {
        currentActiveUserId = FormUtil::GetCallerUserId(factor.callingUid);
    }
    if (currentActiveUserId != factor.record.providerUserId) {
        HILOG_ERROR("not current user:%{public}d, providerUserId:%{public}d, formId:%{public}" PRId64,
            currentActiveUserId, factor.record.providerUserId, factor.formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS