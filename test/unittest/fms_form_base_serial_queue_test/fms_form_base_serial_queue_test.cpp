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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <string>
#include <thread>

#include "queue/form_base_serial_queue.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk::Common;

namespace {
constexpr int32_t WAIT_TIMEOUT_MS = 2000;
constexpr int32_t TASK_DELAY_MS = 500;
constexpr int32_t CANCEL_VERIFY_TIMEOUT_MS = 1100;

class TaskSyncHelper {
public:
    TaskSyncHelper() : taskExecuted(false) {}

    std::function<void()> CreateTask()
    {
        return [this]() {
            taskExecuted = true;
            std::lock_guard<std::mutex> lock(mtx);
            cv.notify_one();
        };
    }

    bool WaitForResult(int32_t timeoutMs = WAIT_TIMEOUT_MS)
    {
        std::unique_lock<std::mutex> lock(mtx);
        return cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this]() {
            return taskExecuted.load();
        });
    }

    bool IsTaskExecuted() const { return taskExecuted.load(); }
    void Reset() { taskExecuted = false; }

private:
    std::atomic<bool> taskExecuted;
    std::mutex mtx;
    std::condition_variable cv;
};

class FmsFormBaseSerialQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormBaseSerialQueueTest::SetUpTestCase()
{}

void FmsFormBaseSerialQueueTest::TearDownTestCase()
{}

void FmsFormBaseSerialQueueTest::SetUp()
{}

void FmsFormBaseSerialQueueTest::TearDown()
{}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleTask_001
 * @tc.desc: Verify ScheduleTask with zero delay and task executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleTask_001 start";
    FormBaseSerialQueue queue("test_queue_001");
    TaskSyncHelper helper;
    EXPECT_TRUE(queue.ScheduleTask(0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Task should execute after scheduling";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleTask_001 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleTask_002
 * @tc.desc: Verify ScheduleTask returns false when ms causes overflow
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleTask_002 start";
    FormBaseSerialQueue queue("test_queue_002");
    TaskSyncHelper helper;
    uint64_t overflowMs = std::numeric_limits<uint64_t>::max();
    EXPECT_FALSE(queue.ScheduleTask(overflowMs, helper.CreateTask()));
    EXPECT_FALSE(helper.IsTaskExecuted()) << "Task should not execute on overflow failure";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleTask_002 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_001
 * @tc.desc: Verify ScheduleDelayTask with int64_t key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_001 start";
    FormBaseSerialQueue queue("test_queue_delay_001");
    TaskSyncHelper helper;
    TaskKey key = static_cast<int64_t>(123456789);
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Delay task with int64_t key should execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_001 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_002
 * @tc.desc: Verify ScheduleDelayTask with pair<int64_t, int64_t> key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_002 start";
    FormBaseSerialQueue queue("test_queue_delay_002");
    TaskSyncHelper helper;
    TaskKey key = std::make_pair(100L, 200L);
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Delay task with pair key should execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_002 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_003
 * @tc.desc: Verify ScheduleDelayTask with string key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_003 start";
    FormBaseSerialQueue queue("test_queue_delay_003");
    TaskSyncHelper helper;
    TaskKey key = std::string("test_task_key");
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Delay task with string key should execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_003 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_004
 * @tc.desc: Verify ScheduleDelayTask returns false when ms causes overflow
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_004 start";
    FormBaseSerialQueue queue("test_queue_delay_004");
    TaskSyncHelper helper;
    TaskKey key = static_cast<int64_t>(999);
    uint64_t overflowMs = std::numeric_limits<uint64_t>::max();
    EXPECT_FALSE(queue.ScheduleDelayTask(key, overflowMs, helper.CreateTask()));
    EXPECT_FALSE(helper.IsTaskExecuted()) << "Task should not execute on overflow failure";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_004 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_005
 * @tc.desc: Verify ScheduleDelayTask replaces existing task with same key
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_005 start";
    FormBaseSerialQueue queue("test_queue_delay_005");
    TaskKey key = static_cast<int64_t>(555);
    std::atomic<bool> task1Executed(false);
    TaskSyncHelper helper;

    auto task1 = [&task1Executed]() {
        task1Executed = true;
    };

    EXPECT_TRUE(queue.ScheduleDelayTask(key, 100, task1));
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 50, helper.CreateTask()));

    EXPECT_TRUE(helper.WaitForResult()) << "Task2 should execute after replacement";
    EXPECT_FALSE(task1Executed) << "Task1 should not execute after being replaced";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_005 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_CancelDelayTask_001
 * @tc.desc: Verify CancelDelayTask cancels task and task does not execute
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_CancelDelayTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_CancelDelayTask_001 start";
    FormBaseSerialQueue queue("test_queue_cancel_001");
    TaskKey key = static_cast<int64_t>(777);
    TaskSyncHelper helper;
    EXPECT_TRUE(queue.ScheduleDelayTask(key, TASK_DELAY_MS, helper.CreateTask()));
    EXPECT_TRUE(queue.CancelDelayTask(key));
    EXPECT_FALSE(helper.WaitForResult(CANCEL_VERIFY_TIMEOUT_MS)) << "Cancelled task should not execute";
    EXPECT_FALSE(helper.IsTaskExecuted()) << "Cancelled task should not execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_CancelDelayTask_001 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_CancelDelayTask_002
 * @tc.desc: Verify CancelDelayTask returns false when task does not exist
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_CancelDelayTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_CancelDelayTask_002 start";
    FormBaseSerialQueue queue("test_queue_cancel_002");
    TaskKey key = static_cast<int64_t>(888);
    EXPECT_FALSE(queue.CancelDelayTask(key));
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_CancelDelayTask_002 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_Constructor_001
 * @tc.desc: Verify FormBaseSerialQueue constructor works with valid queue name
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_Constructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_Constructor_001 start";
    FormBaseSerialQueue queue("constructor_test_queue");
    TaskSyncHelper helper;
    EXPECT_TRUE(queue.ScheduleTask(0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Constructor test task should execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_Constructor_001 end";
}

/**
 * @tc.name: FmsFormBaseSerialQueueTest_ScheduleDelayTask_PairStringKey_001
 * @tc.desc: Verify ScheduleDelayTask with pair<int64_t, string> key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBaseSerialQueueTest, FmsFormBaseSerialQueueTest_ScheduleDelayTask_PairStringKey_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_PairStringKey_001 start";
    FormBaseSerialQueue queue("test_queue_pair_string");
    TaskSyncHelper helper;
    TaskKey key = std::make_pair(static_cast<int64_t>(300), std::string("event_name"));
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, helper.CreateTask()));
    EXPECT_TRUE(helper.WaitForResult()) << "Delay task with pair<string> key should execute";
    GTEST_LOG_(INFO) << "FmsFormBaseSerialQueueTest_ScheduleDelayTask_PairStringKey_001 end";
}
}