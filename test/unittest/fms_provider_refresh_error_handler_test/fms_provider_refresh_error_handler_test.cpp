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
#include <gmock/gmock.h>

#define private public
#define protected public
#include "form_provider/error_handler/provider_refresh_error_handler.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"
#include "data_center/form_data_mgr.h"
#include "form_provider/form_provider_mgr.h"
#include "common/retry_policy/retry_policy.h"
#undef private
#undef protected

#include "mock_i_remote_object.h"
#include "mock_form_data_mgr.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 100;
const int32_t IPC_ERR_DEAD_OBJECT = 32;
const int32_t IPC_ERR_SERVICE_DIED = 29189;
const int32_t DISCONNECT_ERROR = -1;
const std::string BUNDLE_NAME = "com.example.test";
const std::string MODULE_NAME = "module";
}

class MockFormProviderMgr : public FormProviderMgr {
public:
    MockFormProviderMgr() = default;
    ~MockFormProviderMgr() = default;

    MOCK_METHOD3(ConnectAmsForRefresh, ErrCode(const int64_t formId, const FormRecord &record, const Want &want));
};

class FmsProviderRefreshErrorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    FormRecord CreateDefaultFormRecord();
    void SetupGetFormRecordMock(const FormRecord &formRecord, bool returnValue = true);

    // Helper methods
    void VerifyRetryPolicy(int64_t formId, bool expectedSend, bool expectedDisconnect,
                           int expectedRetryCount, bool expectedNeedRetry);
    void SetupPolicyState(int64_t formId, bool sendFailed, bool disconnectFailed, bool resetCount = true);
    void SetRetryCountToMax(int64_t formId, int maxCount);
    void VerifyNoPolicy(int64_t formId);

protected:
    std::shared_ptr<FormProviderRefreshErrorHandler> handler_;
    std::shared_ptr<MockFormDataMgr> mockFormDataMgr_;
    std::shared_ptr<MockFormProviderMgr> mockFormProviderMgr_;
};

void FmsProviderRefreshErrorHandlerTest::SetUpTestCase() {}
void FmsProviderRefreshErrorHandlerTest::TearDownTestCase() {}

void FmsProviderRefreshErrorHandlerTest::SetUp()
{
    handler_ = FormProviderErrorHandlerFactory::GetRefreshHandler();
    mockFormDataMgr_ = std::make_shared<MockFormDataMgr>();
    mockFormProviderMgr_ = std::make_shared<MockFormProviderMgr>();
    MockFormDataMgr::obj = mockFormDataMgr_;
}

void FmsProviderRefreshErrorHandlerTest::TearDown()
{
    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());
    testing::Mock::VerifyAndClearExpectations(mockFormProviderMgr_.get());
    handler_.reset();
    mockFormDataMgr_.reset();
    mockFormProviderMgr_.reset();
    MockFormDataMgr::obj = nullptr;
}

FormRecord FmsProviderRefreshErrorHandlerTest::CreateDefaultFormRecord()
{
    FormRecord formRecord;
    formRecord.formId = FORM_ID;
    formRecord.bundleName = BUNDLE_NAME;
    formRecord.moduleName = MODULE_NAME;
    return formRecord;
}

void FmsProviderRefreshErrorHandlerTest::SetupGetFormRecordMock(const FormRecord &formRecord, bool returnValue)
{
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
            .WillOnce(DoAll([&](int64_t, FormRecord &record) { record = formRecord; }, Return(returnValue)));
}

void FmsProviderRefreshErrorHandlerTest::VerifyRetryPolicy(int64_t formId, bool expectedSend,
    bool expectedDisconnect, int expectedRetryCount, bool expectedNeedRetry)
{
    auto it = handler_->retryPolicyMap_.find(formId);
    EXPECT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.sendRequestFailed_, expectedSend);
    EXPECT_EQ(it->second.disconnectFailed_, expectedDisconnect);
    EXPECT_EQ(it->second.GetRetryCount(), expectedRetryCount);
    EXPECT_EQ(it->second.NeedRetry(), expectedNeedRetry);
}

void FmsProviderRefreshErrorHandlerTest::SetupPolicyState(int64_t formId, bool sendFailed,
    bool disconnectFailed, bool resetCount)
{
    auto &policy = handler_->EnsureRetryPolicy(formId);
    policy.sendRequestFailed_ = sendFailed;
    policy.disconnectFailed_ = disconnectFailed;
    if (resetCount) {
        policy.Reset();
    }
}

void FmsProviderRefreshErrorHandlerTest::SetRetryCountToMax(int64_t formId, int maxCount)
{
    auto &policy = handler_->EnsureRetryPolicy(formId);
    for (int i = 0; i < maxCount; i++) {
        policy.IncrementRetryCount();
    }
    EXPECT_EQ(policy.GetRetryCount(), maxCount);
    EXPECT_TRUE(policy.IsRetryLimitReached());
}

void FmsProviderRefreshErrorHandlerTest::VerifyNoPolicy(int64_t formId)
{
    EXPECT_EQ(handler_->retryPolicyMap_.find(formId), handler_->retryPolicyMap_.end());
}

/**
 * @tc.name: HandleConnectError_AllBranches_001
 * @tc.desc: Verify HandleConnectError returns false for null, dead, and valid remoteObject,
 *           never creates retry policy.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleConnectError_AllBranches_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleConnectError_AllBranches_001 start";

    Want want;

    // Branch: null remote → false, no policy
    EXPECT_FALSE(handler_->HandleConnectError(FORM_ID, nullptr, want));
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 0);

    // Branch: dead remote → false, no policy
    sptr<MockIRemoteObject> deadRemote = new MockIRemoteObject();
    ASSERT_NE(deadRemote, nullptr);
    EXPECT_CALL(*deadRemote, IsObjectDead()).WillOnce(Return(true));
    EXPECT_FALSE(handler_->HandleConnectError(FORM_ID, deadRemote, want));
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 0);
    testing::Mock::VerifyAndClearExpectations(deadRemote);

    // Branch: valid remote → false, no policy
    sptr<MockIRemoteObject> validRemote = new MockIRemoteObject();
    ASSERT_NE(validRemote, nullptr);
    EXPECT_FALSE(handler_->HandleConnectError(FORM_ID, validRemote, want));
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 0);

    GTEST_LOG_(INFO) << "HandleConnectError_AllBranches_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_NonDeathError_001
 * @tc.desc: Verify HandleSendRequestFailed returns false for non-death error codes
 *           (0, -1, 999) without creating retry policy.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleSendRequestFailed_NonDeathError_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_NonDeathError_001 start";

    Want want;

    for (int errorCode : {0, -1, 999}) {
        EXPECT_FALSE(handler_->HandleSendRequestFailed(FORM_ID, errorCode, want));
    }
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 0);

    GTEST_LOG_(INFO) << "HandleSendRequestFailed_NonDeathError_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_DeadObject_001
 * @tc.desc: Verify HandleSendRequestFailed with IPC death error codes (32, 29189) sets
 *           sendRequestFailed=true, increments retryCount, returns true (waiting for disconnect).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleSendRequestFailed_DeadObject_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 start";

    Want want;

    // errorCode=32 (IPC_ERR_DEAD_OBJECT)
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, false, 1, false);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // errorCode=29189 (IPC_ERR_SERVICE_DIED) - same flow
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_SERVICE_DIED, want));
    VerifyRetryPolicy(FORM_ID, true, false, 1, false);

    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_DualSignalAndRetryLimit_001
 * @tc.desc: Verify HandleSendRequestFailed: (1) disconnectFailed pre-set → dual-signal confirmed,
 *           NeedRetry=true, ScheduleRetry called; (2) retryCount >= max → erase policy, return false.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleSendRequestFailed_DualSignalAndRetryLimit_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DualSignalAndRetryLimit_001 start";

    Want want;

    // Branch: disconnectFailed pre-set → dual-signal confirmed, NeedRetry=true
    SetupPolicyState(FORM_ID, false, true, true);
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, true, 1, true);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Branch: retryCount >= maxRetryCount → erase policy, return false
    SetupPolicyState(FORM_ID, false, false, false);
    SetRetryCountToMax(FORM_ID, 3);
    EXPECT_FALSE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyNoPolicy(FORM_ID);

    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DualSignalAndRetryLimit_001 end";
}

/**
 * @tc.name: HandleDisconnectError_AllBranches_001
 * @tc.desc: Verify HandleDisconnectError: (1) no prior SendRequest → returns false;
 *           (2) sendRequestFailed=true + NeedRetry → dual-signal confirmed, ScheduleRetry;
 *           (3) sendRequestFailed=true + retryLimitReached → erase policy, return true.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleDisconnectError_AllBranches_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError_AllBranches_001 start";

    Want want;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject();
    ConnectState state = ConnectState::CONNECTED;

    // Branch: no prior SendRequest → returns false, policy created with disconnectFailed=true
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, false, true, 0, false);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Branch: sendRequestFailed=true, NeedRetry=true → dual-signal confirmed, return true
    SetupPolicyState(FORM_ID, true, false, true);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, true, true, 0, true);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Branch: sendRequestFailed=true, retryLimitReached → erase policy, return true
    SetupPolicyState(FORM_ID, true, false, false);
    SetRetryCountToMax(FORM_ID, 3);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyNoPolicy(FORM_ID);

    GTEST_LOG_(INFO) << "HandleDisconnectError_AllBranches_001 end";
}

/**
 * @tc.name: DualSignal_AllScenarios_001
 * @tc.desc: Verify dual-signal mechanism: (1) send→disconnect → confirmed;
 *           (2) disconnect→send → confirmed; (3) retry limit across signals;
 *           (4) policy removal between signals.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, DualSignal_AllScenarios_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DualSignal_AllScenarios_001 start";

    Want want;
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject();
    ConnectState state = ConnectState::CONNECTED;

    // Scenario 1: send first → disconnect → dual-signal confirmed
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, false, 1, false);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, true, true, 1, true);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Scenario 2: disconnect first → returns false; then send → dual-signal confirmed
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, false, true, 0, false);
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, true, 1, true);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Scenario 3: retry limit across signals → no more retry scheduling
    SetupPolicyState(FORM_ID, false, false, false);
    for (int i = 0; i < 2; i++) {
        handler_->retryPolicyMap_[FORM_ID].IncrementRetryCount();
    }
    EXPECT_FALSE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyNoPolicy(FORM_ID);
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, false, true, 0, false);

    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Scenario 4: policy removal between signals → second signal gets fresh policy
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, false, 1, false);
    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, false, true, 0, false);

    GTEST_LOG_(INFO) << "DualSignal_AllScenarios_001 end";
}

/**
 * @tc.name: ExecuteRefreshRetry_AllBranches_001
 * @tc.desc: Verify ExecuteRefreshRetry: (1) no policy → skip; (2) FormRecord not found → erase;
 *           (3) FormRecord found → ConnectAmsForRefresh called.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, ExecuteRefreshRetry_AllBranches_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ExecuteRefreshRetry_AllBranches_001 start";

    Want want;

    // Branch: no policy in map → skip retry
    VerifyNoPolicy(FORM_ID);
    handler_->ExecuteRefreshRetry(FORM_ID, want);
    VerifyNoPolicy(FORM_ID);

    // Branch: FormRecord not found → erase policy
    SetupPolicyState(FORM_ID, true, true, false);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(FORM_ID, _)).WillOnce(Return(false));
    handler_->ExecuteRefreshRetry(FORM_ID, want);
    VerifyNoPolicy(FORM_ID);
    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());

    // Branch: FormRecord found → ConnectAmsForRefresh called, policy preserved
    SetupPolicyState(FORM_ID, true, true, false);
    handler_->retryPolicyMap_[FORM_ID].IncrementRetryCount();
    FormRecord formRecord = CreateDefaultFormRecord();
    SetupGetFormRecordMock(formRecord, true);
    handler_->ExecuteRefreshRetry(FORM_ID, want);
    VerifyRetryPolicy(FORM_ID, true, true, 1, true);
    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());

    GTEST_LOG_(INFO) << "ExecuteRefreshRetry_AllBranches_001 end";
}

/**
 * @tc.name: StaticMethods_IsRemoteDead_001
 * @tc.desc: Verify IsRemoteDead returns true for 32/29189 and false for others.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, StaticMethods_IsRemoteDead_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StaticMethods_IsRemoteDead_001 start";

    // IsRemoteDead: death codes → true
    EXPECT_TRUE(FormProviderConnectionErrorHandler::IsRemoteDead(IPC_ERR_DEAD_OBJECT));
    EXPECT_TRUE(FormProviderConnectionErrorHandler::IsRemoteDead(IPC_ERR_SERVICE_DIED));
    // IsRemoteDead: non-death codes → false
    EXPECT_FALSE(FormProviderConnectionErrorHandler::IsRemoteDead(0));
    EXPECT_FALSE(FormProviderConnectionErrorHandler::IsRemoteDead(-1));
    EXPECT_FALSE(FormProviderConnectionErrorHandler::IsRemoteDead(999));

    GTEST_LOG_(INFO) << "StaticMethods_IsRemoteDead_001 end";
}

/**
 * @tc.name: EnsureRetryPolicy_CreateAndReturn_001
 * @tc.desc: Verify EnsureRetryPolicy creates new policy when absent and returns existing when present.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, EnsureRetryPolicy_CreateAndReturn_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnsureRetryPolicy_CreateAndReturn_001 start";

    // Create new policy
    auto &policy1 = handler_->EnsureRetryPolicy(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 1);
    EXPECT_EQ(policy1.GetRetryCount(), 0);

    // Return existing policy (same reference)
    auto &policy2 = handler_->EnsureRetryPolicy(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 1);
    EXPECT_EQ(&policy1, &policy2);

    GTEST_LOG_(INFO) << "EnsureRetryPolicy_CreateAndReturn_001 end";
}

/**
 * @tc.name: RemoveRetryPolicy_001
 * @tc.desc: Verify RemoveRetryPolicy removes existing policy and handles non-existent formId.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, RemoveRetryPolicy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveRetryPolicy_001 start";

    // Remove existing policy
    handler_->EnsureRetryPolicy(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 1);
    handler_->RemoveRetryPolicy(FORM_ID);
    VerifyNoPolicy(FORM_ID);

    // Remove non-existent formId → no error
    handler_->RemoveRetryPolicy(999);
    VerifyNoPolicy(FORM_ID);

    GTEST_LOG_(INFO) << "RemoveRetryPolicy_001 end";
}

/**
 * @tc.name: MultipleFormIds_001
 * @tc.desc: Verify handler can manage retry policies for multiple formIds simultaneously.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, MultipleFormIds_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MultipleFormIds_001 start";

    Want want;

    // Send request failed for FORM_ID=100
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    VerifyRetryPolicy(FORM_ID, true, false, 1, false);

    // Send request failed for FORM_ID=200
    EXPECT_TRUE(handler_->HandleSendRequestFailed(200, IPC_ERR_SERVICE_DIED, want));
    VerifyRetryPolicy(200, true, false, 1, false);

    // Both policies exist independently
    EXPECT_EQ(handler_->retryPolicyMap_.size(), 2);

    // Disconnect for FORM_ID=100 → dual-signal confirmed
    sptr<IRemoteObject> remoteObject = new MockIRemoteObject();
    ConnectState state = ConnectState::CONNECTED;
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, remoteObject, want, state));
    VerifyRetryPolicy(FORM_ID, true, true, 1, true);

    // FORM_ID=200 still unaffected
    VerifyRetryPolicy(200, true, false, 1, false);

    GTEST_LOG_(INFO) << "MultipleFormIds_001 end";
}

/**
 * @tc.name: RetryCountIncrement_001
 * @tc.desc: Verify retry count increments correctly across consecutive SendRequest failures.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, RetryCountIncrement_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RetryCountIncrement_001 start";

    Want want;

    // First SendRequest → count=1
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    EXPECT_EQ(handler_->retryPolicyMap_[FORM_ID].GetRetryCount(), 1);

    // Second SendRequest after Reset → count resets and increments
    handler_->retryPolicyMap_[FORM_ID].Reset();
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    EXPECT_EQ(handler_->retryPolicyMap_[FORM_ID].GetRetryCount(), 1);

    GTEST_LOG_(INFO) << "RetryCountIncrement_001 end";
}