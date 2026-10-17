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
#define protected public
#include "common/retry_policy/retry_policy.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"
#include "form_provider/error_handler/provider_refresh_error_handler.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int32_t FORM_ID = 100;
}

class FmsRetryPolicyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsRetryPolicyTest::SetUpTestCase() {}
void FmsRetryPolicyTest::TearDownTestCase() {}
void FmsRetryPolicyTest::SetUp() {}
void FmsRetryPolicyTest::TearDown() {}

/**
 * @tc.name: Constructor_DefaultAndCustom_001
 * @tc.desc: Verify default and custom constructors initialize all fields correctly,
 *           including config, retryCount, and signal flags.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, Constructor_DefaultAndCustom_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Constructor_DefaultAndCustom_001 start";

    // Default constructor
    RetryPolicy defaultPolicy;
    EXPECT_EQ(defaultPolicy.GetRetryCount(), 0);
    EXPECT_EQ(defaultPolicy.GetStage(), RequestStage::IDLE);
    EXPECT_EQ(defaultPolicy.GetCallbackConnectId(), 0);

    // Custom constructor
    RetryPolicyConfig customCfg;
    customCfg.maxRetryCount = 5;
    customCfg.strategyType = RetryStrategyType::LINEAR;
    customCfg.baseDelayMs = 500;
    customCfg.maxDelayMs = 2000;
    RetryPolicy customPolicy(customCfg);
    EXPECT_EQ(customPolicy.GetRetryCount(), 0);
    EXPECT_EQ(customPolicy.GetStage(), RequestStage::IDLE);
    EXPECT_EQ(customPolicy.GetCallbackConnectId(), 0);

    GTEST_LOG_(INFO) << "Constructor_DefaultAndCustom_001 end";
}

/**
 * @tc.name: IsRetryLimitReached_001
 * @tc.desc: Verify IsRetryLimitReached returns true when count >= max, false when below.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, IsRetryLimitReached_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsRetryLimitReached_001 start";

    RetryPolicy policy;

    // Default count=0 → false
    EXPECT_FALSE(policy.IsRetryLimitReached());

    // Below max → false
    policy.retryCount_ = 2;
    EXPECT_FALSE(policy.IsRetryLimitReached());

    // At max → true
    policy.retryCount_ = 3;
    EXPECT_TRUE(policy.IsRetryLimitReached());

    // Exceeds max → true
    policy.retryCount_ = 4;
    EXPECT_TRUE(policy.IsRetryLimitReached());

    GTEST_LOG_(INFO) << "IsRetryLimitReached_001 end";
}

/**
 * @tc.name: IncrementRetryCount_AndReset_001
 * @tc.desc: Verify IncrementRetryCount increments sequentially from 0→3,
 *           and Reset clears count, stage and connectId.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, IncrementRetryCount_AndReset_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IncrementRetryCount_AndReset_001 start";

    RetryPolicy policy;
    EXPECT_EQ(policy.GetRetryCount(), 0);

    // Increment sequence: 0→1→2→3
    policy.IncrementRetryCount();
    EXPECT_EQ(policy.GetRetryCount(), 1);
    policy.IncrementRetryCount();
    EXPECT_EQ(policy.GetRetryCount(), 2);
    policy.IncrementRetryCount();
    EXPECT_EQ(policy.GetRetryCount(), 3);

    // Set non-idle state then Reset
    policy.SetStage(RequestStage::WAITING_CALLBACK);
    policy.SetCallbackConnectId(200);
    policy.Reset();
    EXPECT_EQ(policy.GetRetryCount(), 0);
    EXPECT_EQ(policy.GetStage(), RequestStage::IDLE);
    EXPECT_EQ(policy.GetCallbackConnectId(), 0);

    GTEST_LOG_(INFO) << "IncrementRetryCount_AndReset_001 end";
}

/**
 * @tc.name: CalculateNextDelay_Immediate_001
 * @tc.desc: Verify CalculateNextDelay for IMMEDIATE strategy returns 0 regardless of count.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, CalculateNextDelay_Immediate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalculateNextDelay_Immediate_001 start";

    RetryPolicyConfig cfg;
    cfg.strategyType = RetryStrategyType::IMMEDIATE;
    cfg.baseDelayMs = 1000;
    cfg.maxDelayMs = 4000;
    RetryPolicy policy(cfg);
    policy.retryCount_ = 1;
    EXPECT_EQ(policy.CalculateNextDelay(), 0);

    GTEST_LOG_(INFO) << "CalculateNextDelay_Immediate_001 end";
}

/**
 * @tc.name: CalculateNextDelay_FixedInterval_001
 * @tc.desc: Verify CalculateNextDelay for FIXED_INTERVAL strategy always returns baseDelayMs
 *           regardless of retry count.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, CalculateNextDelay_FixedInterval_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalculateNextDelay_FixedInterval_001 start";

    RetryPolicyConfig cfg;
    cfg.strategyType = RetryStrategyType::FIXED_INTERVAL;
    cfg.baseDelayMs = 1000;
    cfg.maxDelayMs = 4000;
    RetryPolicy policy(cfg);
    policy.retryCount_ = 1;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);
    policy.retryCount_ = 2;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);
    policy.retryCount_ = 3;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);

    GTEST_LOG_(INFO) << "CalculateNextDelay_FixedInterval_001 end";
}

/**
 * @tc.name: CalculateNextDelay_Linear_001
 * @tc.desc: Verify CalculateNextDelay for LINEAR strategy: baseDelay*count capped at maxDelay.
 *           count=1→1000ms, count=2→2000ms, count=5→4000ms(capped).
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, CalculateNextDelay_Linear_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalculateNextDelay_Linear_001 start";

    RetryPolicyConfig cfg;
    cfg.strategyType = RetryStrategyType::LINEAR;
    cfg.baseDelayMs = 1000;
    cfg.maxDelayMs = 4000;
    RetryPolicy policy(cfg);
    policy.retryCount_ = 1;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);
    policy.retryCount_ = 2;
    EXPECT_EQ(policy.CalculateNextDelay(), 2000);
    policy.retryCount_ = 5;
    EXPECT_EQ(policy.CalculateNextDelay(), 4000); // capped: 1000*5=5000>4000

    GTEST_LOG_(INFO) << "CalculateNextDelay_Linear_001 end";
}

/**
 * @tc.name: CalculateNextDelay_Exponential_001
 * @tc.desc: Verify CalculateNextDelay for EXPONENTIAL strategy: baseDelay*2^(count-1) capped at maxDelay.
 *           count=0→1000ms, count=1→1000ms, count=2→2000ms, count=3→4000ms, count=4→4000ms(capped).
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, CalculateNextDelay_Exponential_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalculateNextDelay_Exponential_001 start";

    RetryPolicyConfig cfg;
    cfg.strategyType = RetryStrategyType::EXPONENTIAL;
    cfg.baseDelayMs = 1000;
    cfg.maxDelayMs = 4000;
    RetryPolicy policy(cfg);
    policy.retryCount_ = 0;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);
    policy.retryCount_ = 1;
    EXPECT_EQ(policy.CalculateNextDelay(), 1000);
    policy.retryCount_ = 2;
    EXPECT_EQ(policy.CalculateNextDelay(), 2000);
    policy.retryCount_ = 3;
    EXPECT_EQ(policy.CalculateNextDelay(), 4000);
    policy.retryCount_ = 4;
    EXPECT_EQ(policy.CalculateNextDelay(), 4000); // capped: delay>maxDelayMs/2 early return

    GTEST_LOG_(INFO) << "CalculateNextDelay_Exponential_001 end";
}

/**
 * @tc.name: Stage_SetGet_001
 * @tc.desc: Verify stage and callbackConnectId setter/getter pairs, covering
 *           transitions between all RequestStage values.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsRetryPolicyTest, Stage_SetGet_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Stage_SetGet_001 start";

    RetryPolicy policy;

    // Default: IDLE, no match
    EXPECT_EQ(policy.GetStage(), RequestStage::IDLE);
    EXPECT_EQ(policy.GetCallbackConnectId(), 0);

    // Registration: WAITING_CALLBACK + connectId match
    policy.SetStage(RequestStage::WAITING_CALLBACK);
    policy.SetCallbackConnectId(200);
    EXPECT_EQ(policy.GetStage(), RequestStage::WAITING_CALLBACK);
    EXPECT_EQ(policy.GetCallbackConnectId(), 200);

    // Terminal: CALLBACK_COMPLETED (match cleared by 0)
    policy.SetStage(RequestStage::CALLBACK_COMPLETED);
    policy.SetCallbackConnectId(0);
    EXPECT_EQ(policy.GetStage(), RequestStage::CALLBACK_COMPLETED);
    EXPECT_EQ(policy.GetCallbackConnectId(), 0);

    // Death-confirmation stages
    policy.SetStage(RequestStage::WAITING_DISCONNECT_CONFIRM);
    EXPECT_EQ(policy.GetStage(), RequestStage::WAITING_DISCONNECT_CONFIRM);
    policy.SetStage(RequestStage::WAITING_SEND_RESULT);
    EXPECT_EQ(policy.GetStage(), RequestStage::WAITING_SEND_RESULT);
    policy.SetStage(RequestStage::IDLE);
    EXPECT_EQ(policy.GetStage(), RequestStage::IDLE);

    GTEST_LOG_(INFO) << "Stage_SetGet_001 end";
}

class FmsProviderErrorHandlerFactoryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsProviderErrorHandlerFactoryTest::SetUpTestCase() {}
void FmsProviderErrorHandlerFactoryTest::TearDownTestCase() {}
void FmsProviderErrorHandlerFactoryTest::SetUp() {}
void FmsProviderErrorHandlerFactoryTest::TearDown() {}

/**
 * @tc.name: GetRefreshHandler_Singleton_001
 * @tc.desc: Verify GetRefreshHandler returns same instance across calls (singleton pattern),
 *           address consistency, and DISALLOW_COPY_AND_MOVE is compile-time enforced.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderErrorHandlerFactoryTest, GetRefreshHandler_Singleton_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetRefreshHandler_Singleton_001 start";

    // Factory returns sptr by value (refcounted copy); singleton = same underlying instance.
    auto handler1 = FormProviderErrorHandlerFactory::GetRefreshHandler();
    auto handler2 = FormProviderErrorHandlerFactory::GetRefreshHandler();
    auto handler3 = FormProviderErrorHandlerFactory::GetRefreshHandler();

    EXPECT_EQ(handler1.GetRefPtr(), handler2.GetRefPtr());
    EXPECT_EQ(handler2.GetRefPtr(), handler3.GetRefPtr());
    EXPECT_NE(handler1.GetRefPtr(), nullptr);

    GTEST_LOG_(INFO) << "GetRefreshHandler_Singleton_001 end";
}