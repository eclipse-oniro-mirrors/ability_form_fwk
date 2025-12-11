/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"

namespace {
    bool g_mockGetCallerBundleNameRet = true;
    bool g_mockGetUidByBundleNameRet = true;
    bool g_mockGetAbilityInfoRet = true;
    bool g_mockGetAbilityInfoByActionRet = true;
    bool g_mockGetAbilityInfoByActionRetParamsAbilityInfo = false;
    bool g_mockGetAbilityInfoByActionRetParamsExtensionInfo = false;
}

void MockGetCallerBundleName(bool mockRet)
{
    g_mockGetCallerBundleNameRet = mockRet;
}

void MockGetUidByBundleName(bool mockRet)
{
    g_mockGetUidByBundleNameRet = mockRet;
}

void MockGetAbilityInfo(bool mockRet)
{
    g_mockGetAbilityInfoRet = mockRet;
}

void MockGetAbilityInfoByAction(bool mockRet)
{
    g_mockGetAbilityInfoByActionRet = mockRet;
}

void MockGetAbilityInfoByActionAbilityInfo(bool mockRet)
{
    g_mockGetAbilityInfoByActionRetParamsAbilityInfo = mockRet;
}

void MockGetAbilityInfoByActionExtensionInfo(bool mockRet)
{
    g_mockGetAbilityInfoByActionRetParamsExtensionInfo = mockRet;
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
    if (g_mockGetAbilityInfoByActionRet && g_mockGetAbilityInfoByActionRetParamsAbilityInfo) {
        abilityInfo.name = "name";
    }
    if (g_mockGetAbilityInfoByActionRet && g_mockGetAbilityInfoByActionRetParamsExtensionInfo) {
        extensionAbilityInfo.name = "name";
    }
    return g_mockGetAbilityInfoByActionRet;
}

bool FormBmsHelper::GetAbilityInfo(const AAFwk::Want &want, int32_t userId, AbilityInfo &abilityInfo)
{
    if (g_mockGetAbilityInfoRet) {
        abilityInfo.name = "name";
    }
    return g_mockGetAbilityInfoRet;
}

bool FormBmsHelper::GetBundleInfoWithPermission(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    bundleInfo.reqPermissions.push_back(Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
