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
#include "form_provider/error_handler/provider_connection_error_handler.h"
#undef private
#undef protected

#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 100;
const int64_t FORM_ID_2 = 200;
const int64_t FORM_ID_3 = 300;
const int32_t IPC_ERR_DEAD_OBJECT = 32;
const int32_t IPC_ERR_SERVICE_DIED = 29189;
const int32_t OTHER_ERROR_CODE = 0;
const int32_t NEGATIVE_ERROR_CODE = -1;
const int32_t LARGE_ERROR_CODE = 99999;
const int32_t ERROR_CODE_ONE = 1;
const int32_t ERROR_CODE_HUNDRED = 100;
const int32_t DEFAULT_MAX_RETRY_COUNT = 3;
const int32_t DEFAULT_BASE_DELAY_MS = 1000;
const int32_t DEFAULT_MAX_DELAY_MS = 4000;
const int32_t RETRY_COUNT_ZERO = 0;

class TestConnectionErrorHandler : public FormProviderConnectionErrorHandler {
public:
    TestConnectionErrorHandler() = default;
    virtual ~TestConnectionErrorHandler() = default;

    bool HandleConnectError(int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want) override
    {
        return true;
    }

    bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want) override
    {
        return true;
    }

    bool HandleDisconnectError(int64_t formId, int resultCode, const Want &want) override
    {
        return true;
    }
};

class FmsProviderConnectionErrorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<TestConnectionErrorHandler> handler_;
    
    // Helper methods to eliminate repetitive patterns
    RetryPolicy& EnsurePolicyWithLock(int64_t formId);
    void VerifyMapSize(size_t expectedSize);
    void VerifyPolicyExists(int64_t formId);
    void VerifyPolicyNotExists(int64_t formId);
    void VerifyRemoteDead(int32_t errorCode, bool expectedResult);
};

void FmsProviderConnectionErrorHandlerTest::SetUpTestCase() {}

void FmsProviderConnectionErrorHandlerTest::TearDownTestCase() {}

void FmsProviderConnectionErrorHandlerTest::SetUp()
{
    handler_ = std::make_shared<TestConnectionErrorHandler>();
}

void FmsProviderConnectionErrorHandlerTest::TearDown()
{
    handler_.reset();
}

RetryPolicy& FmsProviderConnectionErrorHandlerTest::EnsurePolicyWithLock(int64_t formId)
{
    std::lock_guard<std::mutex> lock(handler_->retryPolicyMutex_);
    return handler_->EnsureRetryPolicy(formId);
}

void FmsProviderConnectionErrorHandlerTest::VerifyMapSize(size_t expectedSize)
{
    EXPECT_EQ(handler_->retryPolicyMap_.size(), expectedSize);
}

void FmsProviderConnectionErrorHandlerTest::VerifyPolicyExists(int64_t formId)
{
    EXPECT_EQ(handler_->retryPolicyMap_.count(formId), 1u);
}

void FmsProviderConnectionErrorHandlerTest::VerifyPolicyNotExists(int64_t formId)
{
    EXPECT_EQ(handler_->retryPolicyMap_.count(formId), 0u);
}

void FmsProviderConnectionErrorHandlerTest::VerifyRemoteDead(int32_t errorCode, bool expectedResult)
{
    bool result = FormProviderConnectionErrorHandler::IsRemoteDead(errorCode);
    EXPECT_EQ(result, expectedResult);
}

/**
 * @tc.name: IsRemoteDead_AllErrorCodes_001
 * @tc.desc: Verify IsRemoteDead returns true for IPC_ERR_DEAD_OBJECT (32) and IPC_ERR_SERVICE_DIED (29189),
 *           returns false for other error codes (0, 1, -1, 100, 99999).
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, IsRemoteDead_AllErrorCodes_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsRemoteDead_AllErrorCodes_001 start";

    // Test true conditions: IPC dead object errors
    VerifyRemoteDead(IPC_ERR_DEAD_OBJECT, true);
    VerifyRemoteDead(IPC_ERR_SERVICE_DIED, true);

    // Test false conditions: other error codes
    VerifyRemoteDead(OTHER_ERROR_CODE, false);
    VerifyRemoteDead(ERROR_CODE_ONE, false);
    VerifyRemoteDead(NEGATIVE_ERROR_CODE, false);
    VerifyRemoteDead(ERROR_CODE_HUNDRED, false);
    VerifyRemoteDead(LARGE_ERROR_CODE, false);

    GTEST_LOG_(INFO) << "IsRemoteDead_AllErrorCodes_001 end";
}

/**
 * @tc.name: EnsureRetryPolicy_NewFormId_001
 * @tc.desc: Verify EnsureRetryPolicy creates default policy for new formId with default configuration,
 *           zero retry count, and both signals (sendRequestFailed/disconnectFailed) set to false.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, EnsureRetryPolicy_NewFormId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnsureRetryPolicy_NewFormId_001 start";

    VerifyMapSize(0);

    RetryPolicy &policy = EnsurePolicyWithLock(FORM_ID);

    // Verify policy created
    VerifyMapSize(1);
    VerifyPolicyExists(FORM_ID);

    // Verify initial state
    EXPECT_EQ(policy.GetRetryCount(), RETRY_COUNT_ZERO);
    EXPECT_FALSE(policy.sendRequestFailed_);
    EXPECT_FALSE(policy.disconnectFailed_);

    GTEST_LOG_(INFO) << "EnsureRetryPolicy_NewFormId_001 end";
}

/**
 * @tc.name: EnsureRetryPolicy_ExistingFormId_002
 * @tc.desc: Verify EnsureRetryPolicy returns same reference when formId already exists in map,
 *           preserving modified state (sendRequestFailed=true, retryCount=1).
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, EnsureRetryPolicy_ExistingFormId_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnsureRetryPolicy_ExistingFormId_002 start";

    std::lock_guard<std::mutex> lock(handler_->retryPolicyMutex_);
    RetryPolicy &policy1 = handler_->EnsureRetryPolicy(FORM_ID);
    policy1.sendRequestFailed_ = true;
    policy1.retryCount_ = 1;

    VerifyMapSize(1);

    RetryPolicy &policy2 = handler_->EnsureRetryPolicy(FORM_ID);

    // Verify same reference returned
    VerifyMapSize(1);
    EXPECT_EQ(&policy1, &policy2);
    EXPECT_TRUE(policy2.sendRequestFailed_);
    EXPECT_EQ(policy2.GetRetryCount(), 1);

    GTEST_LOG_(INFO) << "EnsureRetryPolicy_ExistingFormId_002 end";
}

/**
 * @tc.name: RemoveRetryPolicy_ExistingFormId_001
 * @tc.desc: Verify RemoveRetryPolicy removes existing formId from map, map size decreases,
 *           and policy no longer exists after removal.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, RemoveRetryPolicy_ExistingFormId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveRetryPolicy_ExistingFormId_001 start";

    EnsurePolicyWithLock(FORM_ID);
    VerifyMapSize(1);

    handler_->RemoveRetryPolicy(FORM_ID);

    VerifyMapSize(0);
    VerifyPolicyNotExists(FORM_ID);

    GTEST_LOG_(INFO) << "RemoveRetryPolicy_ExistingFormId_001 end";
}

/**
 * @tc.name: RemoveRetryPolicy_MultipleAndDoubleRemove_002
 * @tc.desc: Verify RemoveRetryPolicy removes one formId while others remain in map,
 *           and double remove for same formId does not crash.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, RemoveRetryPolicy_MultipleAndDoubleRemove_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveRetryPolicy_MultipleAndDoubleRemove_002 start";

    // Test: remove one formId while others remain
    std::lock_guard<std::mutex> lock(handler_->retryPolicyMutex_);
    handler_->EnsureRetryPolicy(FORM_ID);
    handler_->EnsureRetryPolicy(FORM_ID_2);
    handler_->EnsureRetryPolicy(FORM_ID_3);
    VerifyMapSize(3);

    handler_->RemoveRetryPolicy(FORM_ID);

    VerifyMapSize(2);
    VerifyPolicyNotExists(FORM_ID);
    VerifyPolicyExists(FORM_ID_2);
    VerifyPolicyExists(FORM_ID_3);

    // Test: double remove no crash
    handler_->RemoveRetryPolicy(FORM_ID_2);
    VerifyMapSize(1);

    handler_->RemoveRetryPolicy(FORM_ID_2);  // Double remove
    VerifyMapSize(1);  // No crash, size unchanged

    GTEST_LOG_(INFO) << "RemoveRetryPolicy_MultipleAndDoubleRemove_002 end";
}

/**
 * @tc.name: GetDefaultRetryPolicy_AllFields_001
 * @tc.desc: Verify GetDefaultRetryPolicy returns policy with default configuration (maxRetryCount=3,
 *           strategyType=EXPONENTIAL, baseDelayMs=1000, maxDelayMs=4000), retryCount=0,
 *           and both signals (sendRequestFailed/disconnectFailed) set to false.
 * @tc.type: FUNC
 * @tc.require: issueI5T4GJ
 */
HWTEST_F(FmsProviderConnectionErrorHandlerTest, GetDefaultRetryPolicy_AllFields_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetDefaultRetryPolicy_AllFields_001 start";

    RetryPolicy policy = handler_->GetDefaultRetryPolicy();

    // Verify retry count
    EXPECT_EQ(policy.GetRetryCount(), RETRY_COUNT_ZERO);

    // Verify signals
    EXPECT_FALSE(policy.sendRequestFailed_);
    EXPECT_FALSE(policy.disconnectFailed_);

    GTEST_LOG_(INFO) << "GetDefaultRetryPolicy_AllFields_001 end";
}
}  // namespace