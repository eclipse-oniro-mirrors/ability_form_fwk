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

#include "bms_mgr/form_bms_helper.h"

namespace {
    bool g_mockGetCompileModeRet = true;
}

void MockGetCompileMode(bool mockRet)
{
    g_mockGetCompileModeRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

bool FormBmsHelper::GetCompileMode(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, int32_t &compileMode)
{
    return g_mockGetCompileModeRet;
}
} // namespace AppExecFwk
} // namespace OHOS
