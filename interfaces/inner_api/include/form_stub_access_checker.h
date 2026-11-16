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

#ifndef OHOS_FORM_FWK_FORM_STUB_ACCESS_CHECKER_H
#define OHOS_FORM_FWK_FORM_STUB_ACCESS_CHECKER_H

#include "form_ipc_context.h"
#include "form_permission_policy.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class IStubAccessChecker
 * @brief Abstract interface for IPC permission checking.
 */
class IStubAccessChecker {
public:
    virtual ~IStubAccessChecker() = default;
    /**
     * @brief Check the policy against the caller context.
     * @param policy Access policy to evaluate.
     * @param context Caller identity snapshot.
     * @return Returns ERR_OK on success, err code on deny.
     */
    virtual ErrCode Check(const FormPermissionPolicy &policy, const FormIpcContext &context) = 0;
};

/**
 * @class FailClosedChecker
 * @brief Default checker used until the real checker is installed: rows carrying checks
 *        stay fail-closed denied, while empty pass-through rows return ERR_OK like the real checker.
 */
class FailClosedChecker : public IStubAccessChecker {
public:
    /**
     * @brief Deny rows carrying checks, keeping IPC fail-closed before service startup
     *        installs the checker; empty pass-through rows return ERR_OK like the real checker.
     * @param policy Policy carrying the check count.
     * @param context Unused.
     * @return Returns ERR_OK for empty policies, ERR_APPEXECFWK_FORM_PERMISSION_DENY otherwise.
     */
    ErrCode Check(const FormPermissionPolicy &policy, const FormIpcContext &context) override
    {
        if (policy.checkCount == 0) {
            return ERR_OK;
        }
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }
};

/**
 * @class FormStubAccessChecker
 * @brief Concrete checker for the formmgr SA process.
 */
class FormStubAccessChecker : public IStubAccessChecker {
public:
    /**
     * @brief Check the policy against the caller context.
     * @param policy Access policy to evaluate.
     * @param context Caller identity snapshot.
     * @return Returns ERR_OK on success, err code on deny.
     */
    ErrCode Check(const FormPermissionPolicy &policy, const FormIpcContext &context) override;

private:
    /**
     * @brief Run one step of the policy check list.
     * @param step Check type to run.
     * @param policy The policy carrying the perm name.
     * @param context Caller identity snapshot.
     * @return Returns ERR_OK on success, err code on deny.
     */
    ErrCode CheckPolicyStep(CheckType step, const FormPermissionPolicy &policy, const FormIpcContext &context);
    ErrCode CheckSystemCaller(const FormIpcContext &context);
    ErrCode CheckSystemApp(const FormIpcContext &context);
    ErrCode CheckPermission(const FormPermissionPolicy &policy);
    ErrCode CheckCrossAccount(const FormIpcContext &context);
    ErrCode CheckSaOnly();
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_STUB_ACCESS_CHECKER_H
