/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include "mock_theme_form_client.h"
#include "feature/theme_form/theme_form_client.h"
#include "form_mgr_errors.h.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int64_t TEST_FORM_ID = 123456;
constexpr int32_t TEST_USER_ID = 100;
const std::string TEST_BUNDLE_NAME = "com.form.test";
const std::string TEST_MODULE_NAME = "entry";
const std::string TEST_ABILITY_NAME = "MainAbility";
const std::string TEST_FORM_NAME = "FormTest";
const std::string TEST_THEME_FORM_ID = "theme_form_001";
const std::string TEST_THEME_ID = "theme_001";
}  // namespace

class FmsThemeFormClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsThemeFormClientTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest SetUpTestCase";
}

void FmsThemeFormClientTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest TearDownTestCase";
}

void FmsThemeFormClientTest::SetUp()
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest SetUp";
}

void FmsThemeFormClientTest::TearDown()
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest TearDown";
}

#ifdef THEME_MGR_ENABLE
/**
 * @tc.name: FmsThemeFormClientTest_AddForm_001
 * @tc.desc: Test AddForm without mock object.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_AddForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_AddForm_001 start";
    
    MockThemeFormClient::obj = nullptr;
    
    FormNotifyInfo info;
    info.formId = TEST_FORM_ID;
    info.want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 1);
    info.want.SetParam(Constants::FORM_LOCATION_KEY, 0);
    info.want.SetParam(Constants::PARAM_THEME_THEME_FORM_ID, TEST_THEME_FORM_ID);
    info.want.SetParam(Constants::PARAM_THEME_THEME_ID, TEST_THEME_ID);
    
    auto result = ThemeFormClient::GetInstance().AddForm(info);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_AddForm_001 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_DeleteForms_001
 * @tc.desc: Test DeleteForms without mock object.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_DeleteForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForms_001 start";
    
    MockThemeFormClient::obj = nullptr;
    
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    
    auto result = ThemeFormClient::GetInstance().DeleteForms(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForms_001 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_DeleteForms_002
 * @tc.desc: Test DeleteForms with mock object returning NO_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_DeleteForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForms_002 start";
    
    auto mockObj = std::make_shared<MockThemeFormClient>();
    MockThemeFormClient::obj = mockObj;
    
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    
    EXPECT_CALL(*mockObj, DeleteForms(_))
        .WillOnce(Return(static_cast<int32_t>(NO_ERROR)));
    
    auto result = ThemeFormClient::GetInstance().DeleteForms(formIds);
    EXPECT_EQ(result, static_cast<int32_t>(NO_ERROR));
    
    MockThemeFormClient::obj = nullptr;
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForms_002 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_CleanResource_001
 * @tc.desc: Test CleanResource with both proxy and deathRecipient nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_CleanResource_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_001 start";
    
#define private public
    auto& client = ThemeFormClient::GetInstance();
    client.themeSvcProxy_ = nullptr;
    client.deathRecipient_ = nullptr;
#undef private
    
    EXPECT_NO_FATAL_FAILURE(client.CleanResource());
    
#define private public
    EXPECT_EQ(client.themeSvcProxy_, nullptr);
    EXPECT_EQ(client.deathRecipient_, nullptr);
#undef private
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_001 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_CleanResource_002
 * @tc.desc: Test CleanResource with proxy nullptr and deathRecipient non-null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_CleanResource_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_002 start";
    
#define private public
    auto& client = ThemeFormClient::GetInstance();
    client.themeSvcProxy_ = nullptr;
    client.deathRecipient_ = new ThemeFormDeathRecipient();
#undef private
    
    EXPECT_NO_FATAL_FAILURE(client.CleanResource());
    
#define private public
    EXPECT_EQ(client.themeSvcProxy_, nullptr);
#undef private
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_002 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_CleanResource_003
 * @tc.desc: Test CleanResource with proxy non-null and deathRecipient nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_CleanResource_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_003 start";
    
#define private public
    auto& client = ThemeFormClient::GetInstance();
    sptr<IRemoteObject> remoteObj = nullptr;
    client.themeSvcProxy_ = new ThemeFormServiceProxy(remoteObj);
    client.deathRecipient_ = nullptr;
#undef private
    
    EXPECT_NO_FATAL_FAILURE(client.CleanResource());
    
#define private public
    EXPECT_EQ(client.themeSvcProxy_, nullptr);
#undef private
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_CleanResource_003 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_DeleteForm_001
 * @tc.desc: Test ThemeFormServiceProxy DeleteForm with nullptr remote.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_DeleteForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForm_001 start";
    
    sptr<IRemoteObject> remoteObj = nullptr;
    ThemeFormServiceProxy proxy(remoteObj);
    
    std::vector<long> formIds = {TEST_FORM_ID};
    auto result = proxy.DeleteForm(formIds);
    EXPECT_EQ(result, static_cast<ErrCode>(ERR_FAILED));
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_DeleteForm_001 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_ConvertIntToErrorCode_001
 * @tc.desc: Test ConvertIntToErrorCode with valid error code.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_ConvertIntToErrorCode_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_ConvertIntToErrorCode_001 start";
    
#define private public
    auto& client = ThemeFormClient::GetInstance();
    auto result = client.ConvertIntToErrorCode(static_cast<int32_t>(NO_ERROR));
    EXPECT_EQ(result, NO_ERROR);
    
    result = client.ConvertIntToErrorCode(static_cast<int32_t>(NO_PERMISSION));
    EXPECT_EQ(result, NO_PERMISSION);
    
    result = client.ConvertIntToErrorCode(999999);
    EXPECT_EQ(result, E_UNKNOWN);
#undef private
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_ConvertIntToErrorCode_001 end";
}

/**
 * @tc.name: FmsThemeFormClientTest_OnRemoteSaDied_001
 * @tc.desc: Test OnRemoteSaDied calls CleanResource.
 * @tc.type: FUNC
 */
HWTEST_F(FmsThemeFormClientTest, FmsThemeFormClientTest_OnRemoteSaDied_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_OnRemoteSaDied_001 start";
    
    wptr<IRemoteObject> object(nullptr);
    EXPECT_NO_FATAL_FAILURE(ThemeFormClient::GetInstance().OnRemoteSaDied(object));
    
#define private public
    EXPECT_EQ(ThemeFormClient::GetInstance().themeSvcProxy_, nullptr);
#undef private
    
    GTEST_LOG_(INFO) << "FmsThemeFormClientTest_OnRemoteSaDied_001 end";
}
#endif