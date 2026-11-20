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

#include "form_stub_access_checker.h"

#include <algorithm>
#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode FormStubAccessChecker::Check(const FormPermissionPolicy &policy, const FormIpcContext &context)
{
    bool hasSaBypass = (policy.checkCount > 0 && policy.checks[0] == CheckType::SaBypass);

    // SaBypass at checks[0]: SA callers short-circuit the entire chain.
    if (hasSaBypass && FormUtil::IsSACall()) {
        return ERR_OK;
    }

    const uint8_t startIndex = hasSaBypass ? FormPermissionPolicy::SA_BYPASS_STEP_COUNT : 0;
    for (uint8_t i = startIndex; i < policy.checkCount; ++i) {
        ErrCode result = CheckPolicyStep(policy.checks[i], policy, context);
        if (result != ERR_OK) {
            return result;
        }
    }
    return ERR_OK;
}

ErrCode FormStubAccessChecker::CheckPolicyStep(CheckType step, const FormPermissionPolicy &policy,
                                               const FormIpcContext &context)
{
    switch (step) {
        case CheckType::SaBypass:
            // Unreachable via Check(): SA callers short-circuit earlier and non-SA callers
            // start past checks[0]. Kept for switch totality; ERR_OK keeps the step transparent.
            return ERR_OK;
        case CheckType::SaOnly:
            return CheckSaOnly();
        case CheckType::SystemApp:
            return CheckSystemApp(context);
        case CheckType::SystemCaller:
            return CheckSystemCaller(context);
        case CheckType::Permission:
            return CheckPermission(policy);
        case CheckType::CrossAccount:
            return CheckCrossAccount(context);
        default:
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
}

ErrCode FormStubAccessChecker::CheckSystemCaller(const FormIpcContext &context)
{
    if (FormUtil::IsSACall() ||
        Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.callingTokenId)) {
        return ERR_OK;
    }
    HILOG_ERROR("The caller not system-app,can't use system-api");
    return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
}

ErrCode FormStubAccessChecker::CheckSystemApp(const FormIpcContext &context)
{
    if (Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(context.callingTokenId)) {
        return ERR_OK;
    }
    HILOG_ERROR("The caller not system-app,can't use system-api");
    return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
}

ErrCode FormStubAccessChecker::CheckPermission(const FormPermissionPolicy &policy)
{
    if (FormUtil::VerifyCallingPermission(policy.permName)) {
        return ERR_OK;
    }
    // permName is a string_view and need not be null-terminated; make it printable safely.
    HILOG_ERROR("VerifyCallingPermission failed, permName: %{public}s",
        std::string(policy.permName).c_str());
    return policy.permDenyCode;
}

ErrCode FormStubAccessChecker::CheckCrossAccount(const FormIpcContext &context)
{
    int callingUid = context.callingUid;
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    std::vector<int32_t> foregroundUsers;
    FormUtil::GetForegroundUsers(foregroundUsers);
    if (std::find(foregroundUsers.begin(), foregroundUsers.end(), userId) == foregroundUsers.end()) {
        bool hasPermission = FormUtil::VerifyCallingPermission(
            Constants::PERMISSION_INTERACT_ACROSS_LOCAL_ACCOUNTS);
        if (!hasPermission) {
            HILOG_ERROR("Across local accounts permission failed");
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
        }
    }
    return ERR_OK;
}

ErrCode FormStubAccessChecker::CheckSaOnly()
{
    if (FormUtil::IsSACall()) {
        return ERR_OK;
    }
    HILOG_ERROR("The caller is not a system ability, deny");
    return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
}

}  // namespace AppExecFwk
}  // namespace OHOS
