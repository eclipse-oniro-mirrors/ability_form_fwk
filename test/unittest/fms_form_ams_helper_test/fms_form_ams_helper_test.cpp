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
#include <string>
#include <vector>

#include "want.h"
#define private public
#define protected public
#include "ams_mgr/form_ams_helper.h"
#include "form_mgr_errors.h"
#undef private
#undef protected
#include "mock_ability_manager.h"
#include "inner/mock_fms_form_ams_helper.h"


using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class FmsFormAmsHelperTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormAmsHelperTest::SetUpTestCase() {}

void FmsFormAmsHelperTest::TearDownTestCase() {}

void FmsFormAmsHelperTest::SetUp() {}

void FmsFormAmsHelperTest::TearDown()
{
    MockGetAbilityManager(true);
}

/**
 * @tc.name: FormAmsHelper_DisconnectServiceAbilityDelay_0001
 * @tc.desc: test DisconnectServiceAbilityDelay function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAmsHelperTest, FormAmsHelper_DisconnectServiceAbilityDelay_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAmsHelper_DisconnectServiceAbilityDelay_001 start";
    FormAmsHelper formAmsHelper;
    sptr<AAFwk::IAbilityConnection> connect = nullptr;
    EXPECT_EQ(ERR_OK, formAmsHelper.DisconnectServiceAbilityDelay(connect));
    GTEST_LOG_(INFO) << "FormAmsHelper_DisconnectServiceAbilityDelay_001 end";
}

/**
 * @tc.name: FormAmsHelper_DisconnectAbilityTask_001
 * @tc.desc: test DisconnectAbilityTask function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAmsHelperTest, FormAmsHelper_DisconnectAbilityTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAmsHelper_DisconnectAbilityTask_001 start";
    FormAmsHelper formAmsHelper;
    sptr<AAFwk::IAbilityConnection> connect = nullptr;
    formAmsHelper.DisconnectAbilityTask(connect);
    GTEST_LOG_(INFO) << "FormAmsHelper_DisconnectAbilityTask_001 end";
}

/**
 * @tc.name: FormAmsHelper_StartAbilityOnlyUIAbility_001
 * @tc.desc: test StartAbilityOnlyUIAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAmsHelperTest, FormAmsHelper_StartAbilityOnlyUIAbility_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_001 start";
    FormAmsHelper formAmsHelper;
    Want want;
    int32_t userId = 100;
    MockGetAbilityManager(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formAmsHelper.StartAbilityOnlyUIAbility(want, userId));
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_001 end";
}

/**
 * @tc.name: FormAmsHelper_StartAbilityOnlyUIAbility_002
 * @tc.desc: test StartAbilityOnlyUIAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAmsHelperTest, FormAmsHelper_StartAbilityOnlyUIAbility_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_002 start";
    FormAmsHelper formAmsHelper;
    Want want;
    want.SetFlags(Want::FLAG_ABILITY_CONTINUATION);
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formAmsHelper.StartAbilityOnlyUIAbility(want, userId));
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_002 end";
}

/**
 * @tc.name: FormAmsHelper_StartAbilityOnlyUIAbility_003
 * @tc.desc: test StartAbilityOnlyUIAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAmsHelperTest, FormAmsHelper_StartAbilityOnlyUIAbility_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_003 start";
    FormAmsHelper formAmsHelper;
    Want want;
    int32_t userId = 100;
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbility_ = ERR_OK;
    formAmsHelper.abilityManager_ = mockAmsMgr;
    EXPECT_EQ(ERR_OK, formAmsHelper.StartAbilityOnlyUIAbility(want, userId));
    GTEST_LOG_(INFO) << "FormAmsHelper_StartAbilityOnlyUIAbility_003 end";
}
} // namespace AppExecFwk
} // namespace OHOS
