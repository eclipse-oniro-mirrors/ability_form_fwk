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

#include "common/mock_form_util.h"
#include "mock_form_data_mgr.h"
#include "form_refresh/mock_form_refresh_mgr.h"

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
}  // namespace AppExecFwk
}  // namespace OHOS
