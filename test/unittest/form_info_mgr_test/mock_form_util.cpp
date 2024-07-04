/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_mgr_errors.h"
#include "form_util.h"
#include "fms_log_wrapper.h"

namespace {
bool g_isSACall = true;
bool g_verifyCallingPermission = true;
}

void MockIsSACall(bool mockRet)
{
    g_isSACall = mockRet;
}

void MockVerifyCallingPermission(bool mockRet)
{
    g_verifyCallingPermission = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
bool FormUtil::IsSACall()
{
    GTEST_LOG_(INFO) << "IsSACall called " << g_isSACall;
    return g_isSACall;
}

bool FormUtil::VerifyCallingPermission(const std::string &permissionName)
{
    GTEST_LOG_(INFO) << "VerifyCallingPermission called " << g_verifyCallingPermission;
    return g_verifyCallingPermission;
}
} // namespace AppExecFwk
} // namespace OHOS