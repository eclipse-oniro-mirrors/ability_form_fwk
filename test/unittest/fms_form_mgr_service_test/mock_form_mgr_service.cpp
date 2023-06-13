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

#include "form_mgr_service.h"
#include "form_mgr_errors.h"
#include "form_util.h"
#include "fms_log_wrapper.h"

namespace {
bool g_checkAcrossLocalAccountsPermission = true;
}

void MockCheckAcrossLocalAccountsPermission(bool mockRet)
{
    g_checkAcrossLocalAccountsPermission = mockRet;
}
namespace OHOS {
namespace AppExecFwk {
bool FormMgrService::CheckAcrossLocalAccountsPermission() const
{
    GTEST_LOG_(INFO) << "CheckAcrossLocalAccountsPermission called " << g_checkAcrossLocalAccountsPermission;
    return g_checkAcrossLocalAccountsPermission;
}

} // namespace AAFwk
} // namespace OHOS