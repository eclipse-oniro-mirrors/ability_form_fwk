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
#include "form_refresh/batch_refresh/batch_refresh_mgr.h"
#include "form_refresh/batch_refresh/strategy/default_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/delay_stagger_strategy.h"
#include "form_refresh/batch_refresh/strategy/visible_delay_stagger_strategy.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_mgr_errors.h"
#include "batch_refresh/mock_default_stagger_strategy.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class FmsBatchRefreshMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsBatchRefreshMgrTest::SetUpTestCase()
{
}

void FmsBatchRefreshMgrTest::TearDownTestCase()
{
}

void FmsBatchRefreshMgrTest::SetUp()
{
}

void FmsBatchRefreshMgrTest::TearDown()
{
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_GetStaggerStrategy_001
 * @tc.desc: Verify GetStaggerStrategy returns DefaultStaggerStrategy for DEFAULT type
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, GetStaggerStrategy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetStaggerStrategy_001 start";

    BatchRefreshMgr mgr;
    auto weakStrategy = mgr.GetStaggerStrategy(StaggerStrategyType::DEFAULT);
    auto strategy = weakStrategy.lock();

    ASSERT_NE(strategy, nullptr);
    EXPECT_NE(static_cast<DefaultStaggerStrategy*>(strategy.get()), nullptr);
    EXPECT_FALSE(weakStrategy.expired());

    GTEST_LOG_(INFO) << "GetStaggerStrategy_001 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_GetStaggerStrategy_002
 * @tc.desc: Verify GetStaggerStrategy returns DelayStaggerStrategy for DELAY type
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, GetStaggerStrategy_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetStaggerStrategy_002 start";

    BatchRefreshMgr mgr;
    auto weakStrategy = mgr.GetStaggerStrategy(StaggerStrategyType::DELAY);
    auto strategy = weakStrategy.lock();

    ASSERT_NE(strategy, nullptr);
    EXPECT_NE(static_cast<DelayStaggerStrategy*>(strategy.get()), nullptr);
    EXPECT_FALSE(weakStrategy.expired());

    GTEST_LOG_(INFO) << "GetStaggerStrategy_002 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_GetStaggerStrategy_003
 * @tc.desc: Verify GetStaggerStrategy returns VisibleDelayStaggerStrategy for VISIBLE_DELAY type
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, GetStaggerStrategy_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetStaggerStrategy_003 start";

    BatchRefreshMgr mgr;
    auto weakStrategy = mgr.GetStaggerStrategy(StaggerStrategyType::VISIBLE_DELAY);
    auto strategy = weakStrategy.lock();

    ASSERT_NE(strategy, nullptr);
    EXPECT_NE(static_cast<VisibleDelayStaggerStrategy*>(strategy.get()), nullptr);
    EXPECT_FALSE(weakStrategy.expired());

    GTEST_LOG_(INFO) << "GetStaggerStrategy_003 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_GetStaggerStrategy_004
 * @tc.desc: Verify GetStaggerStrategy returns empty weak_ptr for unknown type
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, GetStaggerStrategy_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetStaggerStrategy_004 start";

    BatchRefreshMgr mgr;
    auto weakStrategy = mgr.GetStaggerStrategy(static_cast<StaggerStrategyType>(999));
    auto strategy = weakStrategy.lock();

    EXPECT_EQ(strategy, nullptr);
    EXPECT_TRUE(weakStrategy.expired());

    GTEST_LOG_(INFO) << "GetStaggerStrategy_004 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_BatchRequestRefresh_001
 * @tc.desc: Verify BatchRequestRefresh returns ERR_OK for empty batch
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, BatchRequestRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchRequestRefresh_001 start";

    BatchRefreshMgr mgr;
    std::vector<RefreshData> batch;
    int32_t ret = mgr.BatchRequestRefresh(FormRefreshType::TYPE_PROVIDER, StaggerStrategyType::DEFAULT, batch);
    EXPECT_EQ(ret, ERR_OK);

    GTEST_LOG_(INFO) << "BatchRequestRefresh_001 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_BatchRequestRefresh_002
 * @tc.desc: Verify BatchRequestRefresh executes DEFAULT strategy successfully
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, BatchRequestRefresh_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchRequestRefresh_002 start";

    MockDefaultStaggerStrategy::obj = std::make_shared<MockDefaultStaggerStrategy>();
    EXPECT_CALL(*MockDefaultStaggerStrategy::obj, ExecuteRefresh(_, _))
        .WillOnce(testing::Return(ERR_OK));
    BatchRefreshMgr mgr;
    std::vector<RefreshData> batch;
    RefreshData data1;
    data1.formId = 1;
    batch.push_back(data1);
    int32_t ret = mgr.BatchRequestRefresh(FormRefreshType::TYPE_PROVIDER, StaggerStrategyType::DEFAULT, batch);
    EXPECT_EQ(ret, ERR_OK);
    MockDefaultStaggerStrategy::obj = nullptr;

    GTEST_LOG_(INFO) << "BatchRequestRefresh_002 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_BatchRequestRefresh_003
 * @tc.desc: Verify BatchRequestRefresh returns error for unknown strategy type
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, BatchRequestRefresh_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchRequestRefresh_003 start";

    BatchRefreshMgr mgr;
    std::vector<RefreshData> batch;
    RefreshData data;
    data.formId = 1;
    batch.push_back(data);
    int32_t ret = mgr.BatchRequestRefresh(
        FormRefreshType::TYPE_PROVIDER, static_cast<StaggerStrategyType>(999), batch);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "BatchRequestRefresh_003 end";
}

/**
 * @tc.name: FmsBatchRefreshMgrTest_BatchRequestRefresh_004
 * @tc.desc: Verify BatchRequestRefresh propagates ExecuteRefresh error
 * @tc.type: FUNC
 */
HWTEST_F(FmsBatchRefreshMgrTest, BatchRequestRefresh_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchRequestRefresh_004 start";

    MockDefaultStaggerStrategy::obj = std::make_shared<MockDefaultStaggerStrategy>();
    EXPECT_CALL(*MockDefaultStaggerStrategy::obj, ExecuteRefresh(_, _))
        .WillOnce(testing::Return(ERR_APPEXECFWK_FORM_INVALID_PARAM));
    BatchRefreshMgr mgr;
    std::vector<RefreshData> batch;
    RefreshData data;
    data.formId = 1;
    batch.push_back(data);
    int32_t ret = mgr.BatchRequestRefresh(FormRefreshType::TYPE_PROVIDER, StaggerStrategyType::DEFAULT, batch);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    MockDefaultStaggerStrategy::obj = nullptr;

    GTEST_LOG_(INFO) << "BatchRequestRefresh_004 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
