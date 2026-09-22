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
#include "accesstoken_kit.h"

#include "fms_log_wrapper.h"

namespace {
uint32_t g_GetHapTokenID = 0;
uint32_t g_HapTokenAttr = 0;
int g_HapTokenInfoRet = OHOS::Security::AccessToken::AccessTokenKitRet::RET_SUCCESS;
}

namespace OHOS {
void MockGetHapTokenID(uint32_t mockRet)
{
    g_GetHapTokenID = mockRet;
}

void MockGetHapTokenInfoAttr(uint32_t mockAttr)
{
    g_HapTokenAttr = mockAttr;
}

void MockGetHapTokenInfoRet(int mockRet)
{
    g_HapTokenInfoRet = mockRet;
}
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace AccessToken {
AccessTokenID AccessTokenKit::GetHapTokenID(int32_t userID, const std::string& bundleName, int32_t instIndex)
{
    GTEST_LOG_(INFO) << "GetHapTokenID called " << g_GetHapTokenID;
    return g_GetHapTokenID;
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo &hapTokenInfo)
{
    GTEST_LOG_(INFO) << "GetHapTokenInfo called " << tokenID << " ret " << g_HapTokenInfoRet;
    hapTokenInfo.tokenAttr = g_HapTokenAttr;
    return g_HapTokenInfoRet;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
