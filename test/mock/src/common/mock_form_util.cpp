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

#include "common/mock_form_util.h"
#include <gtest/gtest.h>
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"

namespace {
    bool g_mockIsActiveUserRet = true;
}

namespace OHOS {
namespace AppExecFwk {
void MockFormUtil::MockIsActiveUser(bool mockRet)
{
    g_mockIsActiveUserRet = mockRet;
}

bool FormUtil::IsActiveUser(int32_t userId)
{
    GTEST_LOG_(INFO) << "FormUtil::IsActiveUser called, returning " << g_mockIsActiveUserRet;
    return g_mockIsActiveUserRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
