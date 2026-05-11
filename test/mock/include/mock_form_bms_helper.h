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

#ifndef OHOS_FORM_FWK_MOCK_FORM_BMS_HELPER_H
#define OHOS_FORM_FWK_MOCK_FORM_BMS_HELPER_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "bundle_mgr_interface.h"
#include "bundle_info.h"
#include "ability_info.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormBmsHelper {
public:
    virtual ~AbstractMockFormBmsHelper() = default;
    virtual sptr<IBundleMgr> GetBundleMgr() = 0;
    virtual ErrCode GetBundleInfoV9(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo) = 0;
    virtual int32_t GetCallerBundleName(std::string &callerBundleName) = 0;
    virtual ErrCode GetApplicationInfo(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo) = 0;
    virtual bool GetAbilityInfoByAction(const std::string &action, int32_t userId,
        AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo) = 0;
    virtual bool GetBundleInfoWithPermission(const std::string &bundleName, int32_t userId,
        BundleInfo &bundleInfo) = 0;
};

class MockFormBmsHelper : public AbstractMockFormBmsHelper {
public:
    static std::shared_ptr<MockFormBmsHelper> obj;
    MockFormBmsHelper() = default;
    ~MockFormBmsHelper() override = default;
    MOCK_METHOD0(GetBundleMgr, sptr<IBundleMgr>());
    MOCK_METHOD3(GetBundleInfoV9, ErrCode(const std::string &bundleName, int32_t userId, BundleInfo &bundleInfo));
    MOCK_METHOD1(GetCallerBundleName, int32_t(std::string &callerBundleName));
    MOCK_METHOD3(GetApplicationInfo, ErrCode(const std::string &bundleName, int32_t userId, ApplicationInfo &appInfo));
    MOCK_METHOD4(GetAbilityInfoByAction, bool(const std::string &action, int32_t userId,
        AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo));
    MOCK_METHOD3(GetBundleInfoWithPermission, bool(const std::string &bundleName, int32_t userId,
        BundleInfo &bundleInfo));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_BMS_HELPER_H
