/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except compliance with the License.
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

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_reminder_agent_refresh_impl.h"
#include "form_refresh/refresh_impl/base_form_refresh.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_refresh/strategy/refresh_config.h"
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "data_center/form_record/form_record.h"
#include "want.h"

#include "mock_form_data_mgr.h"
#include "form_refresh/mock_refresh_control_mgr.h"
#include "gmock/gmock.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t EXPECTED_CONTROL_FLAGS = CONTROL_CHECK_HEALTHY_CONTROL | CONTROL_CHECK_INVISIBLE |
    CONTROL_CHECK_SCREEN_OFF | CONTROL_CHECK_NEED_TO_FRESH;
constexpr int64_t TEST_FORM_ID = 123456L;
constexpr int32_t TEST_CALLING_UID = 20000000;
}

class FmsFormReminderAgentRefreshTest : public Test {
protected:
    void SetUp() override
    {
        MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
        // Default: all control checks pass through (no interception)
        MockRefreshControlMgr::MockIsFormInvisible(false);
        MockRefreshControlMgr::MockIsHealthyControl(false);
        MockRefreshControlMgr::MockIsScreenOff(false);
        MockRefreshControlMgr::MockIsNeedToFresh(true);
        MockRefreshControlMgr::MockIsAddFormFinish(true);
    }
    void TearDown() override
    {
        MockFormDataMgr::obj = nullptr;
    }
};

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_FormRefreshType_001
 * @tc.name: FormRefreshType enum
 * @tc.desc: Verify TYPE_REMINDER_AGENT enum value is 9 (between TYPE_PROVIDER=8 and TYPE_ACCOUNT=10).
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestFormRefreshType_001, TestSize.Level0)
{
    EXPECT_EQ(FormRefreshType::TYPE_REMINDER_AGENT, 9);
    EXPECT_GT(FormRefreshType::TYPE_REMINDER_AGENT, FormRefreshType::TYPE_PROVIDER);
    EXPECT_LT(FormRefreshType::TYPE_REMINDER_AGENT, FormRefreshType::TYPE_ACCOUNT);
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_Config_001
 * @tc.name: RefreshConfig checkTypes
 * @tc.desc: Verify config_.checkTypes contains TYPE_UNTRUST_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_ADD_FINISH.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestConfig_001, TestSize.Level0)
{
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    ASSERT_EQ(impl.config_.checkTypes.size(), 3u);
    // checkTypes = { TYPE_UNTRUST_APP, TYPE_MULTI_ACTIVE_USERS, TYPE_ADD_FINISH }
    EXPECT_NE(std::find(impl.config_.checkTypes.begin(), impl.config_.checkTypes.end(),
        static_cast<int32_t>(TYPE_UNTRUST_APP)), impl.config_.checkTypes.end());
    EXPECT_NE(std::find(impl.config_.checkTypes.begin(), impl.config_.checkTypes.end(),
        static_cast<int32_t>(TYPE_MULTI_ACTIVE_USERS)), impl.config_.checkTypes.end());
    EXPECT_NE(std::find(impl.config_.checkTypes.begin(), impl.config_.checkTypes.end(),
        static_cast<int32_t>(TYPE_ADD_FINISH)), impl.config_.checkTypes.end());
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_Config_002
 * @tc.name: RefreshConfig controlCheckFlags
 * @tc.desc: Verify config_.controlCheckFlags matches the expected bitmask.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestConfig_002, TestSize.Level0)
{
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    EXPECT_EQ(impl.config_.controlCheckFlags, EXPECTED_CONTROL_FLAGS);
    // Verify individual flags
    EXPECT_TRUE(impl.config_.controlCheckFlags & CONTROL_CHECK_HEALTHY_CONTROL);
    EXPECT_TRUE(impl.config_.controlCheckFlags & CONTROL_CHECK_INVISIBLE);
    EXPECT_TRUE(impl.config_.controlCheckFlags & CONTROL_CHECK_SCREEN_OFF);
    EXPECT_TRUE(impl.config_.controlCheckFlags & CONTROL_CHECK_NEED_TO_FRESH);
    // Verify absent flags
    EXPECT_FALSE(impl.config_.controlCheckFlags & CONTROL_CHECK_SYSTEM_OVERLOAD);
    EXPECT_FALSE(impl.config_.controlCheckFlags & CONTROL_CHECK_ADD_FINISH);
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_DoControlCheck_001
 * @tc.name: DoControlCheck sets reminder param and flag
 * @tc.desc: Verify DoControlCheck sets HAS_REMINDER_AGENT_REFRESH_DATA_KEY in want and
 *           SetReminderAgentRefresh before base check.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestDoControlCheck_001, TestSize.Level1)
{
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    RefreshData data;
    data.formId = TEST_FORM_ID;
    data.callingUid = TEST_CALLING_UID;
    data.want = Want();

    EXPECT_CALL(*MockFormDataMgr::obj, SetReminderAgentRefresh(TEST_FORM_ID, true))
        .Times(1);
    // All control checks return false/pass, so base returns ERR_CONTINUE_REFRESH
    auto ret = impl.DoControlCheck(data);
    EXPECT_EQ(ret, ERR_CONTINUE_REFRESH);
    EXPECT_TRUE(data.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
    EXPECT_TRUE(data.want.GetBoolParam(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY, false));
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_DoControlCheck_002
 * @tc.name: DoControlCheck intercepted by healthy control
 * @tc.desc: Verify DoControlCheck sets reminder param and returns ERR_OK when healthy control intercepts.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestDoControlCheck_002, TestSize.Level1)
{
    MockRefreshControlMgr::MockIsHealthyControl(true);
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    RefreshData data;
    data.formId = TEST_FORM_ID;
    data.callingUid = TEST_CALLING_UID;
    data.want = Want();

    EXPECT_CALL(*MockFormDataMgr::obj, SetReminderAgentRefresh(TEST_FORM_ID, true))
        .Times(1);
    auto ret = impl.DoControlCheck(data);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(data.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_DoControlCheck_003
 * @tc.name: DoControlCheck intercepted by invisible
 * @tc.desc: Verify DoControlCheck sets reminder param and returns ERR_OK when invisible intercepts.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestDoControlCheck_003, TestSize.Level1)
{
    MockRefreshControlMgr::MockIsFormInvisible(true);
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    RefreshData data;
    data.formId = TEST_FORM_ID;
    data.callingUid = TEST_CALLING_UID;
    data.want = Want();

    EXPECT_CALL(*MockFormDataMgr::obj, SetReminderAgentRefresh(TEST_FORM_ID, true))
        .Times(1);
    auto ret = impl.DoControlCheck(data);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(data.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_DoControlCheck_004
 * @tc.name: DoControlCheck intercepted by screen off
 * @tc.desc: Verify DoControlCheck sets reminder param and returns ERR_OK when screen off intercepts.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestDoControlCheck_004, TestSize.Level1)
{
    MockRefreshControlMgr::MockIsScreenOff(true);
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    RefreshData data;
    data.formId = TEST_FORM_ID;
    data.callingUid = TEST_CALLING_UID;
    data.want = Want();

    EXPECT_CALL(*MockFormDataMgr::obj, SetReminderAgentRefresh(TEST_FORM_ID, true))
        .Times(1);
    auto ret = impl.DoControlCheck(data);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(data.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
}

/**
 * @tc.number: FmsFormReminderAgentRefreshTest_DoControlCheck_005
 * @tc.name: DoControlCheck intercepted by need-to-fresh false
 * @tc.desc: Verify DoControlCheck sets reminder param and returns ERR_OK when IsNeedToFresh returns false.
 */
HWTEST_F(FmsFormReminderAgentRefreshTest, TestDoControlCheck_005, TestSize.Level1)
{
    MockRefreshControlMgr::MockIsNeedToFresh(false);
    auto &impl = FormReminderAgentRefreshImpl::GetInstance();
    RefreshData data;
    data.formId = TEST_FORM_ID;
    data.callingUid = TEST_CALLING_UID;
    data.want = Want();

    EXPECT_CALL(*MockFormDataMgr::obj, SetReminderAgentRefresh(TEST_FORM_ID, true))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, SetNeedRefresh(TEST_FORM_ID, true))
        .Times(1);
    auto ret = impl.DoControlCheck(data);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(data.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
}
