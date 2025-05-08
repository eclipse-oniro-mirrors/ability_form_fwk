/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#define private public
#include "form_render_serial_queue.h"
#undef private
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;
using namespace std::chrono_literals;

class FormRenderSerialQueueTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FormRenderSerialQueueTest::SetUpTestCase() {}

void FormRenderSerialQueueTest::TearDownTestCase() {}

void FormRenderSerialQueueTest::SetUp() {}

void FormRenderSerialQueueTest::TearDown() {}

/**
 * @tc.name: FormRenderSerialQueueTest_001
 * @tc.desc: function ScheduleTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_001, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto execTime = std::numeric_limits<uint64_t>::max() / 500;
    auto ref = serialQueueTask.ScheduleTask(execTime, []() { GTEST_LOG_(INFO) << "FormRenderRecordTest_001 inner!"; });

    EXPECT_FALSE(ref);
}

/**
 * @tc.name: FormRenderSerialQueueTest_002
 * @tc.desc: function ScheduleTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_002, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto execTime = 0;
    EXPECT_TRUE(serialQueueTask.ScheduleTask(execTime, []() {}));
}

/**
 * @tc.name: FormRenderSerialQueueTest_003
 * @tc.desc: function ScheduleTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_003, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto execTime = 5;
    auto ref =
        serialQueueTask.ScheduleTask(execTime, []() { GTEST_LOG_(INFO) << "FormRenderSerialQueueTest_003 inner!"; });
    EXPECT_TRUE(ref);
}

/**
 * @tc.name: FormRenderSerialQueueTest_004
 * @tc.desc: function ScheduleTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_004, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto execTime = 5;
    bool runFlag = false;
    auto ref = serialQueueTask.ScheduleTask(execTime, [&runFlag]() { runFlag = true; });
    EXPECT_TRUE(ref);
    if (ref) {
        std::this_thread::sleep_for(10000ms);
    }
    EXPECT_TRUE(runFlag);
}

/**
 * @tc.name: FormRenderSerialQueueTest_005
 * @tc.desc: function ScheduleDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_005, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "" };
    auto execTime = 5;
    auto func = []() { GTEST_LOG_(INFO) << "FormRenderSerialQueueTest_005 inner"; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);

    auto taskHandle = serialQueueTask.taskMap_.find(taskName);
    EXPECT_TRUE(taskHandle != serialQueueTask.taskMap_.end());
}

/**
 * @tc.name: FormRenderSerialQueueTest_006
 * @tc.desc: function ScheduleDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_006, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "task1" };
    auto execTime = 0;
    auto func = []() { GTEST_LOG_(INFO) << "FormRenderSerialQueueTest_006 inner"; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);
    auto taskHandle = serialQueueTask.taskMap_.find(taskName);
    EXPECT_TRUE(taskHandle != serialQueueTask.taskMap_.end());
}

/**
 * @tc.name: FormRenderSerialQueueTest_007
 * @tc.desc: function ScheduleDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_007, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "task2" };
    auto execTime = 3;
    auto func = []() { GTEST_LOG_(INFO) << "FormRenderSerialQueueTest_006 inner"; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);
    auto taskHandle = serialQueueTask.taskMap_.find(taskName);
    EXPECT_TRUE(taskHandle != serialQueueTask.taskMap_.end());
}

/**
 * @tc.name: FormRenderSerialQueueTest_008
 * @tc.desc: function ScheduleDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_008, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "task008" };
    auto execTime = 5;
    bool runFlag = false;
    auto func = [&runFlag]() { runFlag = true; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);

    std::this_thread::sleep_for(10000ms);

    EXPECT_TRUE(runFlag);
}

/**
 * @tc.name: FormRenderSerialQueueTest_009
 * @tc.desc: function CancelDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_009, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "task009" };
    auto execTime = 5;
    bool runFlag = false;
    auto func = [&runFlag]() { runFlag = true; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);
    EXPECT_EQ(1, static_cast<int>(serialQueueTask.taskMap_.size()));

    auto cancelTaskName{ "task0099" };
    serialQueueTask.CancelDelayTask(cancelTaskName);

    EXPECT_EQ(1, static_cast<int>(serialQueueTask.taskMap_.size()));
}

/**
 * @tc.name: FormRenderSerialQueueTest_010
 * @tc.desc: function CancelDelayTask test.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderSerialQueueTest, FormRenderSerialQueueTest_010, TestSize.Level0)
{
    std::string queueName = "FormRenderSerialQueueTest";
    FormRenderSerialQueue serialQueueTask(queueName);
    auto taskName{ "task010" };
    auto execTime = 5;
    bool runFlag = false;
    auto func = [&runFlag]() { runFlag = true; };
    serialQueueTask.ScheduleDelayTask(taskName, execTime, func);
    EXPECT_EQ(1, static_cast<int>(serialQueueTask.taskMap_.size()));

    auto cancelTaskName{ "task010" };
    serialQueueTask.CancelDelayTask(cancelTaskName);

    EXPECT_EQ(0, static_cast<int>(serialQueueTask.taskMap_.size()));
}