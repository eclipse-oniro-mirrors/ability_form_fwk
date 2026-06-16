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
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "queue/form_singleton_queue_base.h"
#include "queue/task_wrapper_strategy.h"
#include "queue/form_base_serial_queue.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk::Common;

namespace {
constexpr int32_t WAIT_TIMEOUT_MS = 500;
std::atomic<int32_t> g_queueCounter(0);

class FmsFormSingletonQueueBaseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::string GenerateUniqueQueueName();
};

void FmsFormSingletonQueueBaseTest::SetUpTestCase()
{}

void FmsFormSingletonQueueBaseTest::TearDownTestCase()
{}

void FmsFormSingletonQueueBaseTest::SetUp()
{}

void FmsFormSingletonQueueBaseTest::TearDown()
{}

std::string FmsFormSingletonQueueBaseTest::GenerateUniqueQueueName()
{
    int32_t counter = g_queueCounter.fetch_add(1);
    return "singleton_queue_" + std::to_string(counter);
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_Constructor_001
 * @tc.desc: Verify FormSingletonQueueBase constructor with valid queue name
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_Constructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_001 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleTask(0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Task should execute after scheduling";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_001 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_Constructor_002
 * @tc.desc: Verify FormSingletonQueueBase constructor with nullptr strategy uses default NoWrapStrategy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_Constructor_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_002 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName, nullptr);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleTask(0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Task should execute with nullptr strategy";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_002 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_Constructor_003
 * @tc.desc: Verify FormSingletonQueueBase constructor with custom NoWrapStrategy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_Constructor_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_003 start";
    std::string queueName = GenerateUniqueQueueName();
    auto strategy = std::make_shared<NoWrapStrategy>();
    FormSingletonQueueBase queue(queueName, strategy);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleTask(0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Task should execute with NoWrapStrategy";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_Constructor_003 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_ScheduleTask_001
 * @tc.desc: Verify ScheduleTask with delay executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_ScheduleTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleTask_001 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleTask(50, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Task should execute after delay";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleTask_001 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_ScheduleTask_002
 * @tc.desc: Verify ScheduleTask with XCollieTimeoutStrategy wraps and executes task
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_ScheduleTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleTask_002 start";
    std::string queueName = GenerateUniqueQueueName();
    auto strategy = std::make_shared<XCollieTimeoutStrategy>(5, "TestQueue");
    FormSingletonQueueBase queue(queueName, strategy);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleTask(0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Task should execute with XCollie wrapper";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleTask_002 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_ScheduleDelayTask_001
 * @tc.desc: Verify ScheduleDelayTask with int64_t key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_ScheduleDelayTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_001 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    int64_t formId = 111111;
    TaskKey key = formId;
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Delay task with int64_t key should execute";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_001 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_ScheduleDelayTask_002
 * @tc.desc: Verify ScheduleDelayTask with pair<int64_t, int64_t> key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_ScheduleDelayTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_002 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    TaskKey key = std::make_pair(100L, 200L);
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Delay task with pair key should execute";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_002 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_ScheduleDelayTask_003
 * @tc.desc: Verify ScheduleDelayTask with string key executes correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_ScheduleDelayTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_003 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    TaskKey key = std::string("string_task_key");
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 0, task));
    std::unique_lock<std::mutex> lock(mtx);
    bool result = cv.wait_for(lock, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_TRUE(result) << "Delay task with string key should execute";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_ScheduleDelayTask_003 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_CancelDelayTask_001
 * @tc.desc: Verify CancelDelayTask cancels task and task does not execute
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_CancelDelayTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_CancelDelayTask_001 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    int64_t formId = 222222;
    TaskKey key = formId;
    std::atomic<bool> taskExecuted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto task = [&taskExecuted, &mtx, &cv]() {
        taskExecuted = true;
        std::lock_guard<std::mutex> lock(mtx);
        cv.notify_one();
    };
    EXPECT_TRUE(queue.ScheduleDelayTask(key, 500, task));
    EXPECT_TRUE(queue.CancelDelayTask(key));
    std::unique_lock<std::mutex> lock(mtx);
    bool waitResult = cv.wait_for(lock, std::chrono::milliseconds(600), [&taskExecuted]() {
        return taskExecuted.load();
    });
    EXPECT_FALSE(waitResult) << "Cancelled task should not execute (wait_for should timeout)";
    EXPECT_FALSE(taskExecuted) << "Cancelled task should not execute";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_CancelDelayTask_001 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_CancelDelayTask_002
 * @tc.desc: Verify CancelDelayTask returns false when task does not exist
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_CancelDelayTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_CancelDelayTask_002 start";
    std::string queueName = GenerateUniqueQueueName();
    FormSingletonQueueBase queue(queueName);
    int64_t formId = 333333;
    TaskKey key = formId;
    EXPECT_FALSE(queue.CancelDelayTask(key));
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_CancelDelayTask_002 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_XCollieStrategy_001
 * @tc.desc: Verify XCollieTimeoutStrategy wraps task correctly and wrappedTask executes properly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_XCollieStrategy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_XCollieStrategy_001 start";
    auto strategy = std::make_shared<XCollieTimeoutStrategy>(10, "CustomTag");
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "Wrapped task should execute original task logic";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_XCollieStrategy_001 end";
}

/**
 * @tc.name: FmsFormSingletonQueueBaseTest_NoWrapStrategy_001
 * @tc.desc: Verify NoWrapStrategy returns original task unchanged and executes properly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSingletonQueueBaseTest, FmsFormSingletonQueueBaseTest_NoWrapStrategy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_NoWrapStrategy_001 start";
    auto strategy = std::make_shared<NoWrapStrategy>();
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "NoWrap should execute original task unchanged";
    GTEST_LOG_(INFO) << "FmsFormSingletonQueueBaseTest_NoWrapStrategy_001 end";
}
}