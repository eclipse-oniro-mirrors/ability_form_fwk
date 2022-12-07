/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_bms_helper.h"

#include "form_mgr_errors.h"
#include "ipc_skeleton.h"

namespace {
    bool g_mockGetCallerBundleNameRet = true;
    bool g_mockGetUidByBundleNameRet = true;
    bool g_mockGetAbilityInfoByActionRet = true;
}

void MockGetCallerBundleName(bool mockRet)
{
    g_mockGetCallerBundleNameRet = mockRet;
}

void MockGetUidByBundleName(bool mockRet)
{
    g_mockGetUidByBundleNameRet = mockRet;
}

void MockGetAbilityInfoByAction(bool mockRet)
{
    g_mockGetAbilityInfoByActionRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

int32_t FormBmsHelper::GetCallerBundleName(std::string &callerBundleName)
{
    if (true == g_mockGetCallerBundleNameRet) {
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    return ERR_OK;
}

int32_t FormBmsHelper::GetUidByBundleName(const std::string &bundleName, const int32_t userId)
{
    if (true == g_mockGetUidByBundleNameRet) {
        return INVALID_UID;
    }
    return IPCSkeleton::GetCallingUid();   
}

bool FormBmsHelper::GetAbilityInfoByAction(const std::string &action, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo)
{
    return g_mockGetAbilityInfoByActionRet;
}
} // namespace AppExecFwk
} // namespace OHOS
