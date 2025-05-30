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

#include "accesstoken_kit.h"
#include "fms_log_wrapper.h"

namespace {
int32_t g_GetTokenTypeFlag = 0;
int32_t g_VerifyAccessToken = 0;
}

void MockGetTokenTypeFlag(int32_t mockRet)
{
    g_GetTokenTypeFlag = mockRet;
}

void MockVerifyAccessToken(int32_t mockRet)
{
    g_VerifyAccessToken = mockRet;
}

namespace OHOS {
namespace Security {
namespace AccessToken {
ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID mockRet)
{
    GTEST_LOG_(INFO) << "GetTokenTypeFlag called " << g_GetTokenTypeFlag;
    return static_cast<OHOS::Security::AccessToken::ATokenTypeEnum>(g_GetTokenTypeFlag);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    GTEST_LOG_(INFO) << "VerifyAccessToken called " << g_VerifyAccessToken;
    return g_VerifyAccessToken;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS