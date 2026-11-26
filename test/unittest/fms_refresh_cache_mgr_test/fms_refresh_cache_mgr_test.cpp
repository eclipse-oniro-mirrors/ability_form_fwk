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

#define private public
#include "form_refresh/strategy/refresh_cache_mgr.h"
#undef private

#include "form_constants.h"
#include "common/mock_form_util.h"
#include "mock_form_data_mgr.h"
#include "form_refresh/mock_form_refresh_mgr.h"
#include "gmock/gmock.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class FmsRefreshCacheMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsRefreshCacheMgrTest::SetUpTestCase()
{
}

void FmsRefreshCacheMgrTest::TearDownTestCase()
{
}

void FmsRefreshCacheMgrTest::SetUp()
{
    MockFormUtil::MockIsActiveUser(true);
}

void FmsRefreshCacheMgrTest::TearDown()
{
    MockFormDataMgr::obj.reset();
    MockFormRefreshMgr::obj.reset();
}

/**
 * @tc.name: FmsRefreshCacheMgrTest_ConsumeInvisibleFlag_001
 * @tc.desc: Verify ConsumeInvisibleFlag with empty records returns early,
 *           and non-active user does not trigger FormWant::MergeWantParams
 * @tc.type: FUNC
 */
HWTEST_F(FmsRefreshCacheMgrTest, ConsumeInvisibleFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_001 start";

    MockFormRefreshMgr::MockBatchRequestRefresh(std::vector<int32_t>());

    RefreshCacheMgr mgr;
    int32_t userId = 100;

    std::vector<FormRecord> emptyRecords;
    mgr.ConsumeInvisibleFlag(emptyRecords, userId);

    MockFormUtil::MockIsActiveUser(false);

    std::vector<FormRecord> visibleFormRecords;
    FormRecord record;
    record.formId = 1;
    record.isTimerRefresh = true;
    record.isHostRefresh = true;
    FormWant initialWant;
    initialWant.SetParam("test_key", std::string("test_value"));
    initialWant.SetParam("another_key", 100);
    record.refreshWantMap[1] = initialWant;
    visibleFormRecords.push_back(record);

    mgr.ConsumeInvisibleFlag(visibleFormRecords, userId);

    auto it = visibleFormRecords[0].refreshWantMap.find(1);
    ASSERT_NE(it, visibleFormRecords[0].refreshWantMap.end());
    auto resultWant = it->second.GetWant();
    EXPECT_EQ(resultWant.GetStringParam("test_key"), "test_value");
    EXPECT_EQ(resultWant.GetIntParam("another_key", 0), 100);
    EXPECT_EQ(it->second.GetWant().GetParams().GetParams().size(), 2);

    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_001 end";
}

/**
 * @tc.name: FmsRefreshCacheMgrTest_ConsumeInvisibleFlag_002
 * @tc.desc: Verify ConsumeInvisibleFlag sets HAS_REMINDER_AGENT_REFRESH_DATA_KEY in want
 *           when isReminderAgentRefresh is true and isHostRefresh is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRefreshCacheMgrTest, ConsumeInvisibleFlag_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_002 start";

    MockFormRefreshMgr::obj = std::make_shared<MockFormRefreshMgr>();

    std::vector<RefreshData> capturedBatch;
    EXPECT_CALL(*MockFormRefreshMgr::obj, BatchRequestRefresh(_, _, _))
        .WillOnce(DoAll(SaveArg<2>(&capturedBatch), Return(ERR_OK)));

    RefreshCacheMgr mgr;
    int32_t userId = 100;

    FormRecord record;
    record.formId = 2;
    record.isReminderAgentRefresh = true;
    record.isHostRefresh = false;

    std::vector<FormRecord> records;
    records.push_back(record);

    mgr.ConsumeInvisibleFlag(records, userId);

    ASSERT_EQ(capturedBatch.size(), 1u);
    EXPECT_TRUE(capturedBatch[0].want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
    EXPECT_TRUE(capturedBatch[0].want.GetBoolParam(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY, false));

    MockFormRefreshMgr::obj.reset();
    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_002 end";
}

/**
 * @tc.name: FmsRefreshCacheMgrTest_ConsumeInvisibleFlag_003
 * @tc.desc: Verify ConsumeInvisibleFlag merges refreshWantMap and sets
 *           HAS_REMINDER_AGENT_REFRESH_DATA_KEY when both isHostRefresh and
 *           isReminderAgentRefresh are true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRefreshCacheMgrTest, ConsumeInvisibleFlag_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_003 start";

    MockFormRefreshMgr::obj = std::make_shared<MockFormRefreshMgr>();

    std::vector<RefreshData> capturedBatch;
    EXPECT_CALL(*MockFormRefreshMgr::obj, BatchRequestRefresh(_, _, _))
        .WillOnce(DoAll(SaveArg<2>(&capturedBatch), Return(ERR_OK)));

    RefreshCacheMgr mgr;
    int32_t userId = 100;

    FormRecord record;
    record.formId = 3;
    record.isHostRefresh = true;
    record.isReminderAgentRefresh = true;
    FormWant hostWant;
    hostWant.SetParam("host_key", std::string("host_value"));
    record.refreshWantMap[3] = hostWant;

    std::vector<FormRecord> records;
    records.push_back(record);

    mgr.ConsumeInvisibleFlag(records, userId);

    ASSERT_EQ(capturedBatch.size(), 1u);
    EXPECT_EQ(capturedBatch[0].want.GetStringParam("host_key"), "host_value");
    EXPECT_TRUE(capturedBatch[0].want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
    EXPECT_TRUE(capturedBatch[0].want.GetBoolParam(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY, false));

    MockFormRefreshMgr::obj.reset();
    GTEST_LOG_(INFO) << "ConsumeInvisibleFlag_003 end";
}

/**
 * @tc.name: FmsRefreshCacheMgrTest_ConsumeHealthyControlFlag_001
 * @tc.desc: Verify ConsumeHealthyControlFlag sets HAS_REMINDER_AGENT_REFRESH_DATA_KEY in want
 *           when isRefreshDuringDisableForm and isReminderAgentRefresh are both true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRefreshCacheMgrTest, ConsumeHealthyControlFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConsumeHealthyControlFlag_001 start";

    MockFormRefreshMgr::obj = std::make_shared<MockFormRefreshMgr>();

    RefreshData capturedData;
    EXPECT_CALL(*MockFormRefreshMgr::obj, RequestRefresh(_, _))
        .WillOnce(DoAll(SaveArg<0>(&capturedData), Return(ERR_OK)));

    RefreshCacheMgr mgr;
    int32_t userId = 100;

    FormRecord record;
    record.formId = 10;
    record.bundleName = "com.example.test";
    record.abilityName = "FormAbility";
    record.isRefreshDuringDisableForm = true;
    record.isReminderAgentRefresh = true;

    std::vector<FormRecord> records;
    records.push_back(record);
    auto it = records.begin();

    mgr.ConsumeHealthyControlFlag(it, userId);

    EXPECT_TRUE(capturedData.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));
    EXPECT_TRUE(capturedData.want.GetBoolParam(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY, false));

    MockFormRefreshMgr::obj.reset();
    GTEST_LOG_(INFO) << "ConsumeHealthyControlFlag_001 end";
}

/**
 * @tc.name: FmsRefreshCacheMgrTest_ConsumeHealthyControlFlag_002
 * @tc.desc: Verify ConsumeHealthyControlFlag does NOT set HAS_REMINDER_AGENT_REFRESH_DATA_KEY
 *           when isRefreshDuringDisableForm is true but isReminderAgentRefresh is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsRefreshCacheMgrTest, ConsumeHealthyControlFlag_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConsumeHealthyControlFlag_002 start";

    MockFormRefreshMgr::obj = std::make_shared<MockFormRefreshMgr>();

    RefreshData capturedData;
    EXPECT_CALL(*MockFormRefreshMgr::obj, RequestRefresh(_, _))
        .WillOnce(DoAll(SaveArg<0>(&capturedData), Return(ERR_OK)));

    RefreshCacheMgr mgr;
    int32_t userId = 100;

    FormRecord record;
    record.formId = 11;
    record.bundleName = "com.example.test";
    record.abilityName = "FormAbility";
    record.isRefreshDuringDisableForm = true;
    record.isReminderAgentRefresh = false;

    std::vector<FormRecord> records;
    records.push_back(record);
    auto it = records.begin();

    mgr.ConsumeHealthyControlFlag(it, userId);

    EXPECT_FALSE(capturedData.want.HasParameter(Constants::HAS_REMINDER_AGENT_REFRESH_DATA_KEY));

    MockFormRefreshMgr::obj.reset();
    GTEST_LOG_(INFO) << "ConsumeHealthyControlFlag_002 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
