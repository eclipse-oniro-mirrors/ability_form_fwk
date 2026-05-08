/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mock_form_bms_helper.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "form_mgr_errors.h"
#include "ability_info.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormBmsHelper> MockFormBmsHelper::obj = nullptr;

sptr<IBundleMgr> FormBmsHelper::GetBundleMgr()
{
    GTEST_LOG_(INFO) << "GetBundleMgr called";
    if (AppExecFwk::MockFormBmsHelper::obj) {
        return AppExecFwk::MockFormBmsHelper::obj->GetBundleMgr();
    }
    return nullptr;
}

ErrCode FormBmsHelper::GetBundleInfoV9(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    GTEST_LOG_(INFO) << "GetBundleInfoV9 called";
    if (AppExecFwk::MockFormBmsHelper::obj) {
        return AppExecFwk::MockFormBmsHelper::obj->GetBundleInfoV9(bundleName, userId, bundleInfo);
    }
    return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
}

int32_t FormBmsHelper::GetCallerBundleName(std::string &callerBundleName)
{
    GTEST_LOG_(INFO) << "GetCallerBundleName called";
    if (AppExecFwk::MockFormBmsHelper::obj) {
        return AppExecFwk::MockFormBmsHelper::obj->GetCallerBundleName(callerBundleName);
    }
    return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
}

ErrCode FormBmsHelper::GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo)
{
    GTEST_LOG_(INFO) << "GetApplicationInfo called";
    if (AppExecFwk::MockFormBmsHelper::obj) {
        return AppExecFwk::MockFormBmsHelper::obj->GetApplicationInfo(bundleName, userId, appInfo);
    }
    return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
}

bool FormBmsHelper::GetAbilityInfoByAction(const std::string &action, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo)
{
    GTEST_LOG_(INFO) << "GetAbilityInfoByAction called";
    if (AppExecFwk::MockFormBmsHelper::obj) {
        return AppExecFwk::MockFormBmsHelper::obj->GetAbilityInfoByAction(action, userId,
            abilityInfo, extensionAbilityInfo);
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
