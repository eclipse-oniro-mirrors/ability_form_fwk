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

#include "queue/task_wrapper_strategy.h"
#include "fms_log_wrapper.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk::Common;

namespace {

class TestableXCollieTimeoutStrategy : public ITaskWrapperStrategy {
public:
    explicit TestableXCollieTimeoutStrategy(int32_t timeoutSeconds, std::string tag,
        std::atomic<bool>* timeoutDetected, std::mutex* mtx = nullptr, std::condition_variable* cv = nullptr)
        : timeoutSeconds_(timeoutSeconds), tag_(std::move(tag)),
          timeoutDetected_(timeoutDetected), mtx_(mtx), cv_(cv)
    {}

    std::function<void()> Wrap(std::function<void()> func) override
    {
        return [func = std::move(func), timeout = timeoutSeconds_, tag = tag_,
                timeoutDetected = timeoutDetected_, mtx = mtx_, cv = cv_]() {
            auto timeoutCallback = [timeoutDetected, mtx, cv](void*) {
                if (timeoutDetected != nullptr) {
                    *timeoutDetected = true;
                }
                if (mtx != nullptr && cv != nullptr) {
                    std::lock_guard<std::mutex> lock(*mtx);
                    cv->notify_one();
                }
            };
            int timerId = OHOS::HiviewDFX::XCollie::GetInstance().SetTimer(
                tag, timeout, timeoutCallback, nullptr, OHOS::HiviewDFX::XCOLLIE_FLAG_NOOP);
            func();
            OHOS::HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
        };
    }

private:
    const int32_t timeoutSeconds_;
    const std::string tag_;
    std::atomic<bool>* timeoutDetected_;
    std::mutex* mtx_;
    std::condition_variable* cv_;
};

class FmsTaskWrapperStrategyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsTaskWrapperStrategyTest::SetUpTestCase()
{}

void FmsTaskWrapperStrategyTest::TearDownTestCase()
{}

void FmsTaskWrapperStrategyTest::SetUp()
{}

void FmsTaskWrapperStrategyTest::TearDown()
{}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_NoWrapStrategy_001
 * @tc.desc: Verify NoWrapStrategy wraps and executes task unchanged
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_NoWrapStrategy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_NoWrapStrategy_001 start";
    auto strategy = std::make_shared<NoWrapStrategy>();
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "NoWrapStrategy should execute task unchanged";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_NoWrapStrategy_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Default_001
 * @tc.desc: Verify XCollieTimeoutStrategy with default parameters wraps and executes task
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Default_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Default_001 start";
    auto strategy = std::make_shared<XCollieTimeoutStrategy>();
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "XCollie default strategy should execute task";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Default_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Custom_001
 * @tc.desc: Verify XCollieTimeoutStrategy with custom timeout and tag wraps and executes task
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Custom_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Custom_001 start";
    auto strategy = std::make_shared<XCollieTimeoutStrategy>(10, "CustomTestTag");
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "XCollie custom strategy should execute task";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutStrategy_Custom_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_InterfacePointer_001
 * @tc.desc: Verify ITaskWrapperStrategy interface can hold different strategy implementations
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_InterfacePointer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_InterfacePointer_001 start";
    std::atomic<int32_t> counter(0);
    auto task = [&counter]() {
        counter++;
    };
    std::shared_ptr<ITaskWrapperStrategy> strategy1 = std::make_shared<NoWrapStrategy>();
    auto wrappedTask1 = strategy1->Wrap(task);
    wrappedTask1();
    EXPECT_EQ(counter.load(), 1) << "NoWrapStrategy via interface should execute task";
    std::shared_ptr<ITaskWrapperStrategy> strategy2 = std::make_shared<XCollieTimeoutStrategy>(5, "InterfaceTest");
    auto wrappedTask2 = strategy2->Wrap(task);
    wrappedTask2();
    EXPECT_EQ(counter.load(), 2) << "XCollieTimeoutStrategy via interface should execute task";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_InterfacePointer_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_MultipleWraps_001
 * @tc.desc: Verify Wrap method can be called multiple times on same strategy
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_MultipleWraps_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_MultipleWraps_001 start";
    auto strategy = std::make_shared<NoWrapStrategy>();
    std::atomic<int32_t> counter(0);
    auto task1 = [&counter]() { counter++; };
    auto task2 = [&counter]() { counter += 10; };
    auto wrappedTask1 = strategy->Wrap(task1);
    auto wrappedTask2 = strategy->Wrap(task2);
    wrappedTask1();
    wrappedTask2();
    EXPECT_EQ(counter.load(), 11) << "Multiple wraps should execute both tasks";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_MultipleWraps_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_XCollieTimeoutScenario_001
 * @tc.desc: Verify XCollieTimeoutStrategy timeout scenario where task exceeds timeout threshold
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_XCollieTimeoutScenario_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutScenario_001 start";
    std::atomic<bool> timeoutDetected(false);
    std::atomic<bool> taskExecuted(false);
    std::atomic<bool> taskStarted(false);
    std::mutex mtx;
    std::condition_variable cv;
    auto strategy = std::make_shared<TestableXCollieTimeoutStrategy>(
        1, "TimeoutTest", &timeoutDetected, &mtx, &cv);
    auto task = [&taskExecuted, &taskStarted]() {
        taskStarted = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    std::unique_lock<std::mutex> lock(mtx);
    bool waitResult = cv.wait_for(lock, std::chrono::milliseconds(1200), [&timeoutDetected]() {
        return timeoutDetected.load();
    });
    EXPECT_TRUE(taskStarted) << "Timeout scenario: task should start";
    EXPECT_TRUE(waitResult) << "Timeout scenario: XCollie callback should be triggered";
    EXPECT_TRUE(timeoutDetected) << "Timeout scenario: XCollie should detect timeout";
    EXPECT_TRUE(taskExecuted) << "Timeout scenario: task should complete even after timeout";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieTimeoutScenario_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_XCollieWithinTimeout_001
 * @tc.desc: Verify XCollieTimeoutStrategy task executes successfully within timeout threshold
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_XCollieWithinTimeout_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieWithinTimeout_001 start";
    auto strategy = std::make_shared<XCollieTimeoutStrategy>(2, "WithinTimeout");
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "Task within timeout should execute successfully";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieWithinTimeout_001 end";
}

/**
 * @tc.name: FmsTaskWrapperStrategyTest_XCollieBorderlineTimeout_001
 * @tc.desc: Verify XCollieTimeoutStrategy task near timeout threshold executes successfully
 * @tc.type: FUNC
 */
HWTEST_F(FmsTaskWrapperStrategyTest, FmsTaskWrapperStrategyTest_XCollieBorderlineTimeout_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieBorderlineTimeout_001 start";
    auto strategy = std::make_shared<XCollieTimeoutStrategy>(1, "BorderlineTest");
    std::atomic<bool> taskExecuted(false);
    auto task = [&taskExecuted]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(900));
        taskExecuted = true;
    };
    auto wrappedTask = strategy->Wrap(task);
    wrappedTask();
    EXPECT_TRUE(taskExecuted) << "Task near timeout threshold should execute";
    GTEST_LOG_(INFO) << "FmsTaskWrapperStrategyTest_XCollieBorderlineTimeout_001 end";
}
}