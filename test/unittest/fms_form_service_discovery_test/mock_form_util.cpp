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

#include <gtest/gtest.h>
#include <string>

#include "common/util/form_util.h"
#include "bundle_constants.h"
#include "fms_log_wrapper.h"

namespace {
int32_t g_getCurrentAccountId = 100;
int32_t g_getCallerUserId = 100;
} // namespace

namespace OHOS {
namespace AppExecFwk {

void MockGetCurrentAccountIdRet(int32_t userId)
{
    g_getCurrentAccountId = userId;
}

void MockGetCallerUserId(int32_t userId)
{
    g_getCallerUserId = userId;
}

int FormUtil::GetCurrentAccountId()
{
    GTEST_LOG_(INFO) << "Mock GetCurrentAccountId " << g_getCurrentAccountId;
    return g_getCurrentAccountId;
}

int32_t FormUtil::GetCallerUserId(const int callingUid)
{
    GTEST_LOG_(INFO) << "Mock GetCallerUserId " << g_getCallerUserId;
    return g_getCallerUserId;
}

bool FormUtil::IsSACall()
{
    return true;
}

bool FormUtil::VerifyCallingPermission(std::string_view permissionName)
{
    return true;
}

} // namespace AppExecFwk
} // namespace OHOS
