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
#include <memory>
#include "form_host/form_mgr_host_adapter.h"
#include "inner/mock_form_db_cache.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormMgrHostAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FmsFormMgrHostAdapterTest::SetUp()
{}

void FmsFormMgrHostAdapterTest::TearDown()
{}

/**
 * @tc.name: FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_001
 * @tc.desc: test GetFormIdsByFormLocation returns empty vector when no forms exist
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrHostAdapterTest, FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_001 start";

    std::vector<std::string> formIds;
    int32_t formInfoUserId = 100;
    int32_t callingUserId = 100;
    MockGetAllFormInfoSize(2, formInfoUserId);

    FormMgrHostAdapter::GetInstance().GetFormIdsByFormLocation(
        callingUserId, Constants::FormLocation::DESKTOP, formIds);
    EXPECT_TRUE(formIds.empty());

    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_001 end";
}

/**
 * @tc.name: FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_002
 * @tc.desc: test GetFormIdsByFormLocation with different calling UserId
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrHostAdapterTest, FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_002 start";

    std::vector<std::string> formIds;
    int32_t formInfoUserId = 100;
    int32_t callingUserId = 200;
    MockGetAllFormInfoSize(1, formInfoUserId);

    FormMgrHostAdapter::GetInstance().GetFormIdsByFormLocation(
        callingUserId, Constants::FormLocation::DESKTOP, formIds);
    EXPECT_TRUE(formIds.empty());

    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_002 end";
}

/**
 * @tc.name: FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_003
 * @tc.desc: test GetFormIdsByFormLocation with form location
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrHostAdapterTest, FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_003 start";

    std::vector<std::string> formIds;
    int32_t formInfoUserId = 100;
    int32_t callingUserId = 100;
    MockGetAllFormInfoSize(1, formInfoUserId);

    FormMgrHostAdapter::GetInstance().GetFormIdsByFormLocation(
        callingUserId, Constants::FormLocation::FORM_CENTER, formIds);
    EXPECT_TRUE(formIds.empty());

    FormMgrHostAdapter::GetInstance().GetFormIdsByFormLocation(
        callingUserId, Constants::FormLocation::DESKTOP, formIds);
    EXPECT_EQ(formIds.size(), Constants::MAX_RECORD_PER_HOST);

    GTEST_LOG_(INFO) << "FmsFormMgrHostAdapterTest_GetFormIdsByFormLocation_003 end";
}
}