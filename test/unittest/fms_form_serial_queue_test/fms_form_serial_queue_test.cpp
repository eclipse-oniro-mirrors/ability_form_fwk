/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include <limits>

#include "common/util/form_serial_queue.h"
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
    EXPECT_EQ(false, queue->ScheduleTask(std::numeric_limits<uint64_t>::max(), task));
    GTEST_LOG_(INFO) << "FmsFormSerialQueueTest_ScheduleTask_001 end";
}

}
