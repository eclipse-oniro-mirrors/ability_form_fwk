/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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
#include <gmock/gmock.h>

#include "form_info_mgr.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockGetFormsInfoByModuleRet = true;
    bool g_mockGetFormsInfoByModuleParam = false;
}

void MockGetFormsInfoByModule(bool mockRet)
{
    g_mockGetFormsInfoByModuleRet = mockRet;
}

void MockGetFormsInfoByModuleParam(bool mockRet)
{
    g_mockGetFormsInfoByModuleParam = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
ErrCode FormInfoMgr::GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
                                          std::vector<FormInfo> &formInfos)
{
    if (true == g_mockGetFormsInfoByModuleRet) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    if (g_mockGetFormsInfoByModuleParam) {
        FormInfo formInfo1 = {};
        formInfo1.defaultFlag = false;
        formInfo1.abilityName = "ability";
        formInfo1.moduleName = "aa";
        formInfo1.name = "aa";
        formInfo1.supportDimensions.push_back(1);
        FormInfo formInfo2 = {};
        formInfo2.defaultFlag = true;
        formInfo2.abilityName = "ability";
        formInfo2.moduleName = "aa";
        formInfo2.name = "aa";
        formInfo2.supportDimensions.push_back(1);
        formInfos.push_back(formInfo1);
        formInfos.push_back(formInfo2);
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
