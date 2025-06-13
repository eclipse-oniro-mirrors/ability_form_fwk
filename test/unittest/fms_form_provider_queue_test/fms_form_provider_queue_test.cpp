/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define private public
#include "form_provider/form_provider_queue.h"
#include "common/util/form_serial_queue.h"
#undef private
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
class FmsFormProviderQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};


void FmsFormProviderQueueTest::SetUpTestCase()
{}

void FmsFormProviderQueueTest::TearDownTestCase()
{}

void FmsFormProviderQueueTest::SetUp()
{}

void FmsFormProviderQueueTest::TearDown()
{}

/**
 * @tc.number: FmsFormProviderQueueTest_001
 * @tc.desc: Verify ScheduleTask
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderQueueTest, FmsFormProviderQueueTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_001 start";
    std::shared_ptr<FormProviderQueue> queue = std::make_shared<FormProviderQueue>();
    auto task = [] () {
        GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_001 Task called";
    };
    EXPECT_EQ(true, queue->ScheduleTask(0, task));
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_001 end";
}

/**
 * @tc.number: FmsFormProviderQueueTest_002
 * @tc.desc: Verify ScheduleTask
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderQueueTest, FmsFormProviderQueueTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_002 start";
    std::shared_ptr<FormProviderQueue> queue = std::make_shared<FormProviderQueue>();
    auto task = [] () {
        GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_002 Task called";
    };
    int64_t msg = 1;
    int64_t eventId = 2;
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_002 end";
}

/**
 * @tc.number: FmsFormProviderQueueTest_003
 * @tc.desc: Verify ScheduleTask
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderQueueTest, FmsFormProviderQueueTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_003 start";
    std::shared_ptr<FormProviderQueue> queue = std::make_shared<FormProviderQueue>();
    auto task = [] () {
        GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_002 Task called";
    };
    int64_t msg = 1;
    int64_t eventId = 2;
    queue->CancelDelayTask(std::make_pair(msg, eventId));
    GTEST_LOG_(INFO) << "FmsFormProviderQueueTest_003 end";
}
}
