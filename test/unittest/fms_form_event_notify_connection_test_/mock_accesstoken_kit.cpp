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

namespace {
    int32_t g_mockRegisterPermStateChangeCallback = 0;
    int32_t g_mockUnRegisterPermStateChangeCallback = 0;
}

namespace OHOS {
void MockRegisterPermStateChangeCallback(int32_t mockRet)
{
    g_mockRegisterPermStateChangeCallback = mockRet;
}

void MockUnRegisterPermStateChangeCallback(int32_t mockRet)
{
    g_mockUnRegisterPermStateChangeCallback = mockRet;
}
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace AccessToken {


int32_t AccessTokenKit::RegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    (void)callback;
    return g_mockRegisterPermStateChangeCallback;
}

int32_t AccessTokenKit::UnRegisterPermStateChangeCallback(
    const std::shared_ptr<PermStateChangeCallbackCustomize>& callback)
{
    (void)callback;
    return g_mockUnRegisterPermStateChangeCallback;
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS