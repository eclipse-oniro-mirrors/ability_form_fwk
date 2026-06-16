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
#include "gmock/gmock.h"
#include "form_refresh/batch_refresh/strategy/delay_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/default_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/visible_delay_stagger_strategy.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_refresh/mock_form_refresh_mgr.h"
#include "form_refresh/mock_refresh_control_mgr.h"
#include "form_refresh/mock_refresh_cache_mgr.h"

using namespace testing::ext;
using ::testing::_;
using ::testing::Return;
namespace OHOS {
namespace AppExecFwk {
class FmsStaggerStrategyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsStaggerStrategyTest::SetUpTestCase()
{
}

void FmsStaggerStrategyTest::TearDownTestCase()
{
}

void FmsStaggerStrategyTest::SetUp()
{
}

void FmsStaggerStrategyTest::TearDown()
{
    MockFormRefreshMgr::obj = nullptr;
}

/**
 * @tc.name: FmsStaggerStrategyTest_DelayExecuteRefresh_001
 * @tc.desc: Verify DelayStaggerStrategy::ExecuteRefresh handles empty batch
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, DelayExecuteRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DelayExecuteRefresh_001 start";

    DelayStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    int32_t ret = strategy.ExecuteRefresh(batch, FormRefreshType::TYPE_PROVIDER);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "DelayExecuteRefresh_001 end";
}

/**
 * @tc.name: FmsStaggerStrategyTest_VisibleFilter_001
 * @tc.desc: Verify VisibleDelayStaggerStrategy::Filter keeps all visible forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, VisibleFilter_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VisibleFilter_001 start";

    MockRefreshControlMgr::MockIsFormInvisible(false);
    VisibleDelayStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    for (int i = 0; i < 2; i++) {
        RefreshData data;
        data.formId = i + 1;
        batch.push_back(data);
    }
    strategy.Filter(batch, FormRefreshType::TYPE_NETWORK);
    EXPECT_EQ(batch.size(), 2);

    GTEST_LOG_(INFO) << "VisibleFilter_001 end";
}

/**
 * @tc.name: FmsStaggerStrategyTest_VisibleFilter_002
 * @tc.desc: Verify VisibleDelayStaggerStrategy::Filter removes all invisible forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, VisibleFilter_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VisibleFilter_002 start";

    MockRefreshControlMgr::MockIsFormInvisible(true);
    MockRefreshCacheMgr::MockAddFlagByInvisible();
    VisibleDelayStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    for (int i = 0; i < 2; i++) {
        RefreshData data;
        data.formId = i + 1;
        batch.push_back(data);
    }
    strategy.Filter(batch, FormRefreshType::TYPE_PROVIDER);
    EXPECT_EQ(batch.size(), 0);

    GTEST_LOG_(INFO) << "VisibleFilter_002 end";
}

/**
 * @tc.name: FmsStaggerStrategyTest_DefaultExecuteRefresh_001
 * @tc.desc: Verify DefaultStaggerStrategy::ExecuteRefresh handles empty batch
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, DefaultExecuteRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_001 start";

    DefaultStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    int32_t ret = strategy.ExecuteRefresh(batch, FormRefreshType::TYPE_PROVIDER);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_001 end";
}

/**
 * @tc.name: FmsStaggerStrategyTest_DefaultExecuteRefresh_002
 * @tc.desc: Verify DefaultStaggerStrategy::ExecuteRefresh handles single form
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, DefaultExecuteRefresh_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_002 start";

    auto mockRefreshMgr = std::make_shared<MockFormRefreshMgr>();
    MockFormRefreshMgr::obj = mockRefreshMgr;
    EXPECT_CALL(*mockRefreshMgr, RequestRefresh(_, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));

    DefaultStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    RefreshData data;
    data.formId = 1;
    batch.push_back(data);
    int32_t ret = strategy.ExecuteRefresh(batch, FormRefreshType::TYPE_PROVIDER);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_002 end";
}

/**
 * @tc.name: FmsStaggerStrategyTest_DefaultExecuteRefresh_003
 * @tc.desc: Verify DefaultStaggerStrategy::ExecuteRefresh handles multiple forms failed
 * @tc.type: FUNC
 */
HWTEST_F(FmsStaggerStrategyTest, DefaultExecuteRefresh_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_003 start";

    auto mockRefreshMgr = std::make_shared<MockFormRefreshMgr>();
    MockFormRefreshMgr::obj = mockRefreshMgr;
    EXPECT_CALL(*mockRefreshMgr, RequestRefresh(_, _))
        .Times(2)
        .WillRepeatedly(Return(ERR_APPEXECFWK_FORM_INVALID_PARAM));

    DefaultStaggerStrategy strategy;
    std::vector<RefreshData> batch;
    for (int i = 0; i < 2; i++) {
        RefreshData data;
        data.formId = i + 1;
        batch.push_back(data);
    }
    int32_t ret = strategy.ExecuteRefresh(batch, FormRefreshType::TYPE_PROVIDER);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "DefaultExecuteRefresh_003 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
