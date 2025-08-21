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

#include "mock_form_data_proxy_record_test.h"

using namespace OHOS::AppExecFwk;

namespace {
    int32_t g_currentAccountId = Constants::ANY_USERID;

}

namespace OHOS {
void MockGetCurrentAccountIdRet(int32_t userId)
{
    g_currentAccountId = userId;
}
} // namespace OHOS

namespace OHOS {
namespace AppExecFwk {
int FormUtil::GetCurrentAccountId()
{
    GTEST_LOG_(INFO) << "GetCurrentAccountId called " << g_currentAccountId;
    return g_currentAccountId;
}
} // namespace AppExecFwk
} // namespace OHOS