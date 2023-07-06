/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_serial_queue.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
class FmsFormSerialQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};


void FmsFormSerialQueueTest::SetUpTestCase()
{}

void FmsFormSerialQueueTest::TearDownTestCase()
{}

void FmsFormSerialQueueTest::SetUp()
{}

void FmsFormSerialQueueTest::TearDown()
{}

/**
 * @tc.number: FmsFormSerialQueueTest_ScheduleTask_001
 * @tc.name: ScheduleTask
 * @tc.desc: Verify that the return value is true.(formId is invalid)
 */
HWTEST_F(FmsFormSerialQueueTest, FmsFormSerialQueueTest_ScheduleTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleTask_001 start";
    const std::string queueName = "queue";
    std::shared_ptr<FormSerialQueue> queue = std::make_shared<FormSerialQueue>(queueName.c_str());
    auto task = [] () {
        GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleTask_001 Task called";
    };
    EXPECT_EQ(true, queue->ScheduleTask(0, task));
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleTask_001 end";
}

/**
 * @tc.number: FmsFormSerialQueueTest_ScheduleDelayTask_001
 * @tc.name: ScheduleDelayTask
 * @tc.desc: Verify ScheduleDelayTask
 */
HWTEST_F(FmsFormSerialQueueTest, FmsFormSerialQueueTest_ScheduleDelayTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleDelayTask_001 start";
    const std::string queueName = "queue1";
    std::shared_ptr<FormSerialQueue> queue = std::make_shared<FormSerialQueue>(queueName.c_str());
    EXPECT_NE(nullptr, queue);
    auto task = [] () {
        GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleDelayTask_001 Task called";
    };
    int64_t msg = 1;
    int64_t eventId = 2;
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleDelayTask_001 end";
}

/**
 * @tc.number: FmsFormSerialQueueTest_CancelDelayTask_001
 * @tc.name: ScheduleDelayTask
 * @tc.desc: Verify ScheduleDelayTask
 */
HWTEST_F(FmsFormSerialQueueTest, FmsFormSerialQueueTest_CancelDelayTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_CancelDelayTask_001 start";
    const std::string queueName = "queue1";
    std::shared_ptr<FormSerialQueue> queue = std::make_shared<FormSerialQueue>(queueName.c_str());
    EXPECT_NE(nullptr, queue);
    int64_t msg = 1;
    int64_t eventId = 2;
    queue->CancelDelayTask(std::make_pair(msg, eventId));
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_CancelDelayTask_001 end";
}
}
