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

#include <utility>
#include <vector>

#include "bundle_constants.h"
#include "common/util/form_util.h"

namespace {
bool g_isSACall = false;
bool g_verifyCallingPermission = true;
int32_t g_getCallerUserId = OHOS::AppExecFwk::Constants::ANY_USERID;
std::vector<int32_t> g_foregroundUsers;
}  // namespace

void MockVerifyCallingPermission(bool mockRet)
{
    g_verifyCallingPermission = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

void MockIsSACall(bool mockRet)
{
    g_isSACall = mockRet;
}

void MockGetCallerUserId(int32_t userId)
{
    g_getCallerUserId = userId;
}

void MockGetForegroundUsers(std::vector<int32_t> foregroundUsers)
{
    g_foregroundUsers = std::move(foregroundUsers);
}

bool FormUtil::IsSACall()
{
    GTEST_LOG_(INFO) << "IsSACall called " << g_isSACall;
    return g_isSACall;
}

bool FormUtil::VerifyCallingPermission(std::string_view permissionName)
{
    GTEST_LOG_(INFO) << "VerifyCallingPermission called " << g_verifyCallingPermission;
    return g_verifyCallingPermission;
}

int32_t FormUtil::GetCallerUserId(const int callingUid)
{
    GTEST_LOG_(INFO) << "GetCallerUserId called " << g_getCallerUserId;
    return g_getCallerUserId;
}

void FormUtil::GetForegroundUsers(std::vector<int32_t> &foregroundList)
{
    GTEST_LOG_(INFO) << "GetForegroundUsers called " << g_foregroundUsers.size();
    foregroundList = g_foregroundUsers;
}
}  // namespace AppExecFwk
}  // namespace OHOS
