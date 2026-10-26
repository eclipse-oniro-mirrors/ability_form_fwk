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

#include "inner/mock_napi_common_want.h"

#include <gtest/gtest.h>
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "napi_common_want.h"

namespace {
    bool g_mockUnwrapWantSucceed = false;
    int32_t g_mockUnwrapWantColorMode = -1;
}

void MockUnwrapWant(bool shouldSucceed, int32_t mockColorMode)
{
    g_mockUnwrapWantSucceed = shouldSucceed;
    g_mockUnwrapWantColorMode = mockColorMode;
}

void ResetUnwrapWantMock()
{
    g_mockUnwrapWantSucceed = false;
    g_mockUnwrapWantColorMode = -1;
}

namespace OHOS {
namespace AppExecFwk {

bool UnwrapWant(napi_env env, napi_value param, OHOS::AAFwk::Want &want)
{
    GTEST_LOG_(INFO) << "Mock UnwrapWant called, succeed=" << g_mockUnwrapWantSucceed;
    if (!g_mockUnwrapWantSucceed) {
        return false;
    }
    want.SetParam(OHOS::AppExecFwk::Constants::PARAM_FORM_EDIT_COLOR_MODE, g_mockUnwrapWantColorMode);
    return true;
}

} // namespace AppExecFwk
} // namespace OHOS
