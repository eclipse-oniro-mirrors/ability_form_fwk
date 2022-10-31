/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_kit.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#include "form_db_cache.h"
#include "form_host_interface.h"
#define private public
#include "form_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr_service.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"

#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"
#include "mock_form_host_client.h"
#include "remote_native_token.h"
#include "running_process_info.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;

namespace {
const std::string PERMISSION_NAME_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
const std::string FORM_PROVIDER_BUNDLE_NAME = "com.form.provider.service";

class FmsFormMgrNotifyFormsPrivacyProtectedTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;

protected:
    sptr<MockFormHostClient> token_;
    std::shared_ptr<FormMgrService> formMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
};

void FmsFormMgrNotifyFormsPrivacyProtectedTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
    FormAmsHelper::GetInstance().SetAbilityManager(new MockAbilityMgrService());
}

void FmsFormMgrNotifyFormsPrivacyProtectedTest::TearDownTestCase()
{}

void FmsFormMgrNotifyFormsPrivacyProtectedTest::SetUp()
{
    formMgrServ_->OnStart();
    token_ = new(std::nothrow) MockFormHostClient();

    // Permission install
    int userId = 0;
    auto tokenId = AccessToken::AccessTokenKit::GetHapTokenID(userId, FORM_PROVIDER_BUNDLE_NAME, 0);
    auto flag = OHOS::Security::AccessToken::PERMISSION_USER_FIXED;
    AccessToken::AccessTokenKit::GrantPermission(tokenId, PERMISSION_NAME_REQUIRE_FORM, flag);
}

void FmsFormMgrNotifyFormsPrivacyProtectedTest::TearDown()
{}

/**
 * @tc.number: FmsFormMgrNotifyFormsPrivacyProtectedTest_NotifyFormsPrivacyProtected_001
 * @tc.name: NotifyFormsPrivacyProtected
 * @tc.desc: Verify that the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.info: callerToken is nullptr.
 */
HWTEST_F(FmsFormMgrNotifyFormsPrivacyProtectedTest, NotifyFormsPrivacyProtected_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrNotifyFormsPrivacyProtectedTest_NotifyFormsPrivacyProtected_001 start";
    std::vector<int64_t> formIds;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, false, nullptr));
    GTEST_LOG_(INFO) << "FmsFormMgrNotifyFormsPrivacyProtectedTest_NotifyFormsPrivacyProtected_001 end";
}
}
