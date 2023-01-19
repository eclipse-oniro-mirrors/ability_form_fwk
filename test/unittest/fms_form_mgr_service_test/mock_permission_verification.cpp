/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "permission_verification.h"
#include "hilog_wrapper.h"

namespace {
    bool isSACall = true;
    bool verifyCallingPermission = true;
}

void MockIsSACall(bool mockRet)
{
    isSACall = mockRet;
}

void MockVerifyCallingPermission(bool mockRet)
{
    verifyCallingPermission = mockRet;
}

namespace OHOS {
namespace AAFwk {
bool PermissionVerification::IsSACall() const
{
    GTEST_LOG_(INFO) << "IsSACall called " << isSACall;
    return isSACall;
}

bool PermissionVerification::VerifyCallingPermission(const std::string &permissionName) const
{
    GTEST_LOG_(INFO) << "VerifyCallingPermission called " << verifyCallingPermission;
    return verifyCallingPermission;
}
} // namespace AAFwk
} // namespace OHOS