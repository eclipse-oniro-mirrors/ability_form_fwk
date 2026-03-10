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